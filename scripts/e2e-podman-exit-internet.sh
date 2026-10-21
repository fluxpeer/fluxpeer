#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Run on qa after building the current worktree for x86_64-unknown-linux-musl.
# Only fpe- resources are created; containers receive the binary, never sources.
# Podman's temporary bridge/routes/firewall changes are explicitly authorized.
# Usage: bash scripts/e2e-podman-exit-internet.sh [--keep] [--fault-only]
set -euo pipefail
KEEP=0
FAULT_ONLY=0
for arg in "$@"; do
    case "$arg" in --keep) KEEP=1;; --fault-only) FAULT_ONLY=1;;
        *) echo 'usage: e2e-podman-exit-internet.sh [--keep] [--fault-only]' >&2; exit 2;; esac
done
ROOT="${FLUXPEER_E2E_ROOT:-/opt/ops/fp/e2e}"
BIN="${FLUXPEER_BIN:-$ROOT/bin/fluxpeer}"
export FPE_KEEP="$KEEP" FPE_ROOT="$ROOT" FPE_BIN="$BIN" FPE_FAULT_ONLY="$FAULT_ONLY"
test "$(uname -s)" = Linux
test -x "$BIN"
sudo -n podman version >/dev/null
# Python owns the finally/trap equivalent, including signals and partial setup.
exec python3 - <<'PY'
import datetime, hashlib, ipaddress, json, os, pathlib, re, shlex, signal
import subprocess as sp
import sys, time, traceback, fcntl, random

ROOT = pathlib.Path(os.environ['FPE_ROOT']).resolve()
BIN = pathlib.Path(os.environ['FPE_BIN']).resolve()
# Resource names are shared across roots; serialize before reclaiming --keep.
lock = open('/tmp/fluxpeer-exit-e2e.lock', 'a')
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
KEEP = os.environ['FPE_KEEP'] == '1'
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
OUT = ROOT / 'evidence' / STAMP
OUT.mkdir(parents=True, exist_ok=False)
(ROOT / 'evidence' / 'latest').unlink(missing_ok=True)
(ROOT / 'evidence' / 'latest').symlink_to(STAMP)
P = ['sudo', '-n', 'podman']
IMAGE = 'localhost/fpe-node:t0022'
BASE = 'docker.io/library/debian:trixie-slim'
ADMIN = 'fpe-t0022-test-only'
containers, networks, checks, observations = [], [], [], []
image_created = False
seq = 0
group = 'setup'
state = {}

def run(args, data=None, timeout=40):
    try:
        p = sp.run(args, input=data, text=True, stdout=sp.PIPE,
                   stderr=sp.PIPE, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except sp.TimeoutExpired as e:
        def txt(v): return v.decode(errors='replace') if isinstance(v, bytes) else (v or '')
        return 124, txt(e.stdout), txt(e.stderr) + '\nHARNESS_TIMEOUT\n'

def record(label, args, data=None, timeout=40, secret=False):
    global seq
    rc, out, err = run(args, data, timeout)
    seq += 1
    fname = f'{seq:04d}-{group}-{label}.txt'
    # Do not print enrollment secrets or authorization headers to evidence.
    display = '<credential-bearing request>' if secret else shlex.join(args)
    (OUT / fname).write_text(f'$ {display}\nEXIT_CODE={rc}\nSTDOUT:\n{out}\nSTDERR:\n{err}')
    return rc, out, err, fname

def need(args, data=None, timeout=40):
    rc, out, err = run(args, data, timeout)
    if rc: raise RuntimeError(f'{shlex.join(args)}: rc={rc}\n{out}\n{err}')
    return out

def px(c, *args): return P + ['exec', c] + list(args)

def check(label, args, success=True, timeout=20):
    rc, out, err, fname = record(label, args, timeout=timeout)
    passed = (rc == 0) == success
    checks.append(dict(scenario=group, check=label, expected_rc='0' if success else 'nonzero',
                       actual_rc=rc, verdict='PASS' if passed else 'FAIL', evidence=fname))
    print(f'{group} {label}: {"PASS" if passed else "FAIL"} rc={rc}', flush=True)
    return rc, out

# Avoid reusing a TCP four-tuple within this run, even across scenarios. Each
# failed target gets exactly one fresh curl process with a different local port.
probe_ports = random.SystemRandom().sample(range(20000, 60000), 40000)
PUBLIC_TARGETS = ('https://1.1.1.1', 'https://example.com')
DNS_TARGETS = ('https://example.com', 'https://www.cloudflare.com')
TRACE_TARGETS = ('https://1.1.1.1/cdn-cgi/trace', 'https://1.0.0.1/cdn-cgi/trace')

def public_probe(label, c='fpe-cli', targets=PUBLIC_TARGETS, success=True,
                 max_time=8, kind='https', judge=True):
    if len(set(targets)) < 2: raise ValueError('public probes require distinct targets')
    attempts, replies = [], {}
    for target in targets:
        for attempt in (1, 2):
            port = probe_ports.pop() if kind == 'https' else None
            if kind == 'https':
                args = px(c, 'curl', '--noproxy', '*', '-4', '-fsS', '--max-time', str(max_time),
                          '--local-port', str(port), '-w',
                          '\nLOCAL=%{local_ip}:%{local_port} REMOTE=%{remote_ip} HTTP=%{http_code}\n', target)
            elif kind == 'ping':
                args = px(c, 'ping', '-c', '1', '-W', '2', target)
            elif kind == 'dns':
                args = px(c, 'dig', '+time=2', '+tries=1', '+short', target, 'A')
            else: raise ValueError('unknown probe kind: ' + kind)
            rc, out, err, evidence = record(f'{label}-target-{len(attempts)}-try-{attempt}', args, timeout=max_time + 5)
            reached = rc == 0 and (kind != 'dns' or bool(out.strip()))
            attempts.append(dict(target=target, attempt=attempt, source_port=port,
                                 actual_rc=rc, reached=reached, evidence=evidence))
            if reached:
                replies[target] = out
                break
    reachable = bool(replies)
    passed = reachable == success
    if judge:
        checks.append(dict(scenario=group, check=label, expected='any target reachable' if success else 'all targets blocked',
                           verdict='PASS' if passed else 'FAIL', attempts=attempts))
        print(f'{group} {label}: {"PASS" if passed else "FAIL"}', flush=True)
    else:
        observations.append(dict(scenario=group, check=label, attempts=attempts))
    return (0 if reachable else 1), replies, [a['evidence'] for a in attempts]

def egress_probe(positive):
    _, exits, ae = public_probe('exit-source-ip', 'fpe-exit', TRACE_TARGETS, judge=False)
    _, clients, be = public_probe('client-source-ip', targets=TRACE_TARGETS, judge=False)
    ips = lambda text: re.findall(r'^ip=(.+)$', text, re.M)
    matched, invalid = [], []
    for target, text in clients.items():
        if not ips(text): invalid.append(target)
        elif target in exits:
            if ips(text) == ips(exits[target]): matched.append(target)
            else: invalid.append(target)
    # Transport failure at one target is tolerable; a successful response from
    # the wrong egress (or malformed trace) must never be hidden by another match.
    passed = bool(matched) and not invalid if positive else not clients
    checks.append(dict(scenario=group, check='egress-source-match',
        verdict='PASS' if passed else 'FAIL', evidence=ae + be, matched=matched, invalid=invalid))


def host_snapshot(tag):
    commands = {
        'route': ['ip', 'route'], 'addr': ['ip', '-br', 'addr'],
        'route6': ['ip', '-6', 'route'], 'rules': ['sudo', '-n', 'nft', '-s', 'list', 'ruleset'],
        'sysctl': ['sudo', '-n', 'sysctl', 'net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding'],
        'containers': P + ['ps', '-a', '--format', '{{.ID}} {{.Names}} {{.Status}}'],
        'networks': P + ['network', 'ls', '--format', '{{.ID}} {{.Name}}'],
        'images': P + ['images', '--format', '{{.ID}} {{.Repository}}:{{.Tag}}'],
    }
    snap = {}
    for label, args in commands.items():
        rc, out, err = run(args)
        if rc: raise RuntimeError(f'snapshot {label}: {err}')
        snap[label] = out
        (OUT / f'host-{tag}-{label}.txt').write_text(out)
    return snap

def api(method, path, body=None, token=ADMIN):
    args = px('fpe-ctl', 'curl', '-fsS', '--max-time', '10', '-X', method,
              '-H', 'Content-Type: application/json', '-H', f'Authorization: Bearer {token}')
    if body is not None: args += ['--data', json.dumps(body)]
    args += ['http://127.0.0.1:18080/api/v1' + path]
    out = need(args, timeout=15)
    return json.loads(out) if out.strip() else None

def write_container(c, path, text):
    need(P + ['exec', '-i', c, 'sh', '-c', 'cat > "$1"', 'sh', path], text)

def enroll(c, name):
    invite = api('POST', f'/networks/{state["net"]}/invites', {})
    import base64
    token = 'fp://join/' + base64.urlsafe_b64encode(json.dumps(
        {'ctrl': f'http://{MESH}.10:18080', 'code': invite['code']}).encode()).decode().rstrip('=')
    need(px(c, 'fluxpeer', 'join', token, '--name', name, '--out', '/run/fpe/node.json', '--no-run'))
    return json.loads(need(px(c, 'cat', '/run/fpe/node.json')))

def route(prefix, approve=True):
    r = api('POST', f'/devices/{state["e"]["device_id"]}/routes', {'prefix': prefix})
    if approve: api('POST', f'/routes/{r["id"]}/approve')
    return r['id']

def endpoints(cfg, addr, port):
    api('POST', f'/devices/{cfg["device_id"]}/endpoints', {'endpoints': [f'{addr}:{port}']},
        token=cfg['auth_token'])

def stop(c):
    # PIDs are scoped to a container created by this run, never host processes.
    run(px(c, 'sh', '-c', 'if test -f /run/fpe/node.pid; then '
        'p=$(cat /run/fpe/node.pid); kill -TERM "$p" 2>/dev/null || true; '
        'for n in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$p" 2>/dev/null || break; sleep .2; done; '
        'kill -KILL "$p" 2>/dev/null || true; rm -f /run/fpe/node.pid; fi'))

def stop_pair():
    stop('fpe-cli'); stop('fpe-exit')

def start(c, cfg, file_dns=False):
    write_container(c, '/run/fpe/node.json', json.dumps(cfg))
    # Only the process log is truncated; prior scenario snapshots remain in OUT.
    env = 'FLUXPEER_DNS_BACKEND=resolv ' if file_dns else ''
    need(P + ['exec', '-d', c, 'sh', '-c', 'echo $$ > /run/fpe/node.pid; '
        f'exec env {env}RUST_LOG=info,fp_transport_anytls::health=error fluxpeer node run /run/fpe/node.json > /run/fpe/node.log 2>&1'])

def settings(use_exit='auto', transport='direct', dns=True, port=41841, force_exit=False):
    e, c = dict(state['e']), dict(state['c'])
    for cfg, addr, listen in [(e, f'{MESH}.20', port), (c, f'{MESH}.30', 41840)]:
        cfg.update(tun_name='fpe0', listen_port=listen, advertise=[f'{addr}:{listen}'],
                   prefix_len=24, dns=['1.1.1.1'] if dns else [])
        if transport != 'direct':
            cfg['force_relay'] = True
            if not transport.startswith('directory-'):
                rp = 13443 if transport == 'anytls' else 13479 if transport == 'bond' else 13478
                cfg['relay'] = f'{MESH}.10:{rp}'
                cfg['relay_anytls'] = transport == 'anytls'
                cfg['relay_bond'] = transport == 'bond'
                cfg['relay_node_id'] = 'fluxpeer-relay'
    # AD-1: the exit side needs NO local flag — the control-plane's approved
    # 0.0.0.0/0 route (self_exit) enables its forwarding/NAT dynamically.
    # force_exit exercises the legacy `exit_node: true` local override instead.
    for cfg in (e, c):
        for key in ('exit_node', 'exit_veto', 'use_exit'):
            cfg.pop(key, None)
    if force_exit:
        e['exit_node'] = True
    # AD-2: the client opts INTO an exit explicitly; absent → split-tunnel.
    if use_exit:
        c['use_exit'] = use_exit
    return e, c

def pair(use_exit='auto', transport='direct', dns=True, force_exit=False, port=41841):
    stop_pair()
    e, c = settings(use_exit, transport, dns, port, force_exit)
    # A preexisting LAN-forwarding setup is intentional. S1 then isolates NAT.
    # A separate S1-forward-off control demonstrates LAN forwarding dependency.
    need(px('fpe-exit', 'sysctl', '-w', 'net.ipv4.ip_forward=1'))
    start('fpe-exit', e); start('fpe-cli', c)
    time.sleep(10 if transport == 'direct' else 16)
    observe_counters()

def new_network(name, directory=None):
    stop_pair()
    state.clear()
    state['net'] = api('POST', '/networks', {'name': name})['id']
    state['e'] = enroll('fpe-exit', 'exit-' + name)
    state['c'] = enroll('fpe-cli', 'client-' + name)
    endpoints(state['e'], f'{MESH}.20', 41841)
    endpoints(state['c'], f'{MESH}.30', 41840)
    state['lan_route'] = route(f'{LAN}.0/24')
    state['default_route'] = route('0.0.0.0/0')
    if directory:
        api('POST', '/relays', dict(region='fpe-test', url=f'{MESH}.10:{13443 if directory == "anytls" else 13478}',
            network_id=state['net'], anytls=directory == 'anytls', stun_url=f'{MESH}.10:13478', node_id='fluxpeer-relay'))

def observe_counters():
    # Backend-owned rules already count packets. Read the real tables instead
    # of inserting observers into the obsolete global inet fluxpeer table.
    record('observe-forward-counter', px('fpe-exit', 'iptables', '-w', '10', '-nvxL', 'FORWARD'))
    record('observe-nat-counter', px('fpe-exit', 'iptables', '-w', '10', '-t', 'nat', '-nvxL', 'POSTROUTING'))
    record('observe-native-nft-counters', px('fpe-exit', 'nft', '-a', 'list', 'ruleset'))

def capture(label='after'):
    if 'c' in state:
        cfg = api('GET', f'/devices/{state["c"]["device_id"]}/config', token=state['c']['auth_token'])
        (OUT / f'{group}-{label}-client-config.json').write_text(json.dumps(cfg, indent=2))
    cmds = [
        ('client-route', px('fpe-cli', 'ip', 'route')),
        ('client-route-get', px('fpe-cli', 'ip', 'route', 'get', '1.1.1.1')),
        ('client-route6', px('fpe-cli', 'ip', '-6', 'route')),
        ('exit-ip6tables', px('fpe-exit', 'ip6tables', '-S')),
        ('client-addr', px('fpe-cli', 'ip', '-br', 'addr')),
        ('client-show', px('fpe-cli', 'fluxpeer', 'show', '--json')),
        ('client-tcp-sockets', px('fpe-cli', 'ss', '-tnp')),
        ('client-output-guard', px('fpe-cli', 'nft', 'list', 'ruleset')),
        ('exit-forward', px('fpe-exit', 'sysctl', 'net.ipv4.ip_forward', 'net.ipv4.conf.all.rp_filter',
                           'net.ipv4.conf.default.rp_filter')),
        ('exit-route', px('fpe-exit', 'ip', 'route')),
        ('exit-nft', px('fpe-exit', 'nft', '-a', 'list', 'ruleset')),
        ('exit-iptables-nat', px('fpe-exit', 'iptables', '-S', '-t', 'nat')),
        ('exit-iptables-filter', px('fpe-exit', 'iptables', '-S')),
        ('client-resolv', px('fpe-cli', 'cat', '/etc/resolv.conf')),
        ('client-log', px('fpe-cli', 'tail', '-n', '85', '/run/fpe/node.log')),
        ('exit-log', px('fpe-exit', 'tail', '-n', '85', '/run/fpe/node.log')),
        ('relay-log', px('fpe-ctl', 'tail', '-n', '55', '/run/fpe/relay.log')),
    ]
    for name, cmd in cmds: record(label + '-' + name, cmd)

def probes(positive, mesh_positive=True):
    exit_cfg = api('GET', f'/devices/{state["e"]["device_id"]}/config', token=state['e']['auth_token'])
    check('overlay', px('fpe-cli', 'ping', '-c', '2', '-W', '2', exit_cfg['address_v4']), mesh_positive)
    check('intranet', px('fpe-cli', 'ping', '-c', '2', '-W', '2', f'{LAN}.40'), mesh_positive)
    public_probe('public-ip-https', targets=('https://1.1.1.1', 'https://1.0.0.1'), success=positive)
    public_probe('public-dns-https', targets=DNS_TARGETS, success=positive, max_time=10)
    public_probe('dns-query', targets=('example.com', 'www.cloudflare.com'), kind='dns', success=positive)
    egress_probe(positive)
    capture()

def require_observation(label, passed, evidence):
    checks.append(dict(scenario=group, check=label, verdict='PASS' if passed else 'FAIL', evidence=evidence))
    if not passed: raise RuntimeError('observation failed: ' + label)

def expect_dns(label, expected):
    # Bound asynchronous reconciliation; save the actual final bytes as evidence.
    for _ in range(50):
        rc, text, _ = run(px('fpe-cli', 'cat', '/etc/resolv.conf'))
        if rc == 0 and text == expected: break
        time.sleep(.2)
    rc, text, _, evidence = record(label, px('fpe-cli', 'cat', '/etc/resolv.conf'))
    require_observation(label, rc == 0 and text == expected, evidence)

def dns_lifecycle(crash=False):
    new_network('dns-crash' if crash else 'dns-bind-mount')
    stop_pair()
    original = need(px('fpe-cli', 'cat', '/etc/resolv.conf'))
    baseline = '# fpe DNS baseline\nnameserver 192.0.2.53\noptions timeout:1 attempts:1\n'
    first = '# fluxpeer exit-node\nnameserver 1.1.1.1\n'
    second = '# fluxpeer exit-node\nnameserver 1.0.0.1\n'
    e, c = settings()
    guard_added = False
    try:
        rc, mountinfo, _, evidence = record('resolver-mountinfo', px('fpe-cli', 'cat', '/proc/self/mountinfo'))
        require_observation('resolver-is-podman-bind-mount', rc == 0 and any(
            line.split()[4:5] == ['/etc/resolv.conf'] for line in mountinfo.splitlines()), evidence)
        write_container('fpe-cli', '/etc/resolv.conf', baseline)
        start('fpe-exit', e); start('fpe-cli', c, file_dns=True)
        expect_dns('first-instance-dns-installed', first)
        check('dns-full-tunnel-route', px('fpe-cli', 'sh', '-ec',
              'ip -4 route show | grep -q "^0.0.0.0/1.*dev fpe0"'))
        if crash:
            rc, journal, _, evidence = record('first-dns-journal', px('fpe-cli', 'cat', '/var/lib/fluxpeer/dns/state.json'))
            require_observation('first-owner-persisted', rc == 0 and any(
                owner['iface'] == 'fpe0' for owner in json.loads(journal)['owners']), evidence)
            need(px('fpe-cli', 'sh', '-ec', 'p=$(cat /run/fpe/node.pid); kill -KILL "$p"; '
                    'for n in $(seq 1 50); do test ! -e /proc/"$p" && exit 0; sleep .1; done; exit 1'))
            expect_dns('killed-instance-left-dns', first)
            # A distinct interface must prune the dead owner rather than save A's
            # resolver as B's baseline. Share the same persistent DNS journal.
            c['tun_name'] = 'fpe1'; c['dns'] = ['1.0.0.1']
            need(px('fpe-cli', 'nft', 'insert', 'rule', 'inet', 'fpe_guard', 'output',
                    'oifname', 'fpe1', 'accept', 'comment', '"fpe-dns-second-interface"'))
            guard_added = True
            start('fpe-cli', c, file_dns=True)
            expect_dns('second-instance-dns-installed', second)
            rc, journal, _, evidence = record('second-dns-journal', px('fpe-cli', 'cat', '/var/lib/fluxpeer/dns/state.json'))
            require_observation('dead-owner-pruned', rc == 0 and
                [owner['iface'] for owner in json.loads(journal)['owners']] == ['fpe1'], evidence)
        stop('fpe-cli')
        expect_dns('baseline-restored-after-stop', baseline)
        rc, journal, _, evidence = record('dns-journal-after-stop', px('fpe-cli', 'cat', '/var/lib/fluxpeer/dns/state.json'))
        require_observation('dns-owners-released', rc == 0 and not json.loads(journal)['owners'], evidence)
    finally:
        stop_pair()
        if guard_added:
            rules = json.loads(need(px('fpe-cli', 'nft', '-j', '-a', 'list', 'chain', 'inet', 'fpe_guard', 'output')))
            for item in rules['nftables']:
                rule = item.get('rule', {})
                if rule.get('comment') == 'fpe-dns-second-interface':
                    need(px('fpe-cli', 'nft', 'delete', 'rule', 'inet', 'fpe_guard', 'output', 'handle', str(rule['handle'])))
        # This restoration is harness cleanup, after the independent assertion.
        write_container('fpe-cli', '/etc/resolv.conf', original)

def scenario(name, fn):
    global group
    if os.environ['FPE_FAULT_ONLY'] == '1' and name != 'S4-sysctl-failure': return
    group = name
    print(f'BEGIN {name}', flush=True)
    try: fn()
    except Exception:
        message = traceback.format_exc()
        (OUT / f'{name}-exception.txt').write_text(message)
        checks.append(dict(scenario=name, check='harness-completion', actual_rc=1, verdict='FAIL', error=message))
        print(message, flush=True)
    finally:
        (OUT / 'checks.json').write_text(json.dumps(checks, indent=2))

def cleanup():
    global group
    group = 'cleanup'
    if KEEP:
        print(f'KEEP: retaining resources; evidence {OUT}', flush=True)
        return
    for c in reversed(containers): record('remove-' + c, P + ['rm', '-f', '-t', '0', c])
    for n in reversed(networks): record('remove-' + n, P + ['network', 'rm', n])
    if image_created: record('remove-image', P + ['rmi', IMAGE])
    # Netavark 1.14 leaves global scaffold chains after the last network is
    # removed. Remove only a table this invocation created from an absent state,
    # and only if all other host rules are byte-identical and no container runs.
    marker = 'table inet netavark {'
    current_rules = need(['sudo', '-n', 'nft', '-s', 'list', 'ruleset'])
    if (networks and marker not in before['rules'] and marker in current_rules
            and current_rules.split(marker)[0] == before['rules']
            and not need(P + ['ps', '-q']).strip()):
        record('remove-new-netavark-scaffold', ['sudo', '-n', 'nft', 'delete', 'table', 'inet', 'netavark'])
    after = host_snapshot('after')
    import difflib
    for key, old in before.items():
        delta = ''.join(difflib.unified_diff(old.splitlines(True), after[key].splitlines(True),
                                            fromfile='before-' + key, tofile='after-' + key))
        (OUT / f'host-diff-{key}.txt').write_text(delta)
        checks.append(dict(scenario='cleanup', check='host-' + key + '-unchanged',
            actual_rc=bool(delta), verdict='FAIL' if delta else 'PASS'))
    for label, args in [('containers', P + ['ps', '-a', '--format', '{{.Names}}']),
                        ('networks', P + ['network', 'ls', '--format', '{{.Name}}']),
                        ('images', P + ['images', '--format', '{{.Repository}}:{{.Tag}}'])]:
        rc, out, err, fname = record('remaining-' + label, args)
        matches = [x for x in out.splitlines() if x.startswith('fpe-') or x == IMAGE]
        checks.append(dict(scenario='cleanup', check='no-fpe-' + label, actual_rc=rc,
                           verdict='PASS' if rc == 0 and not matches else 'FAIL', evidence=fname, remaining=matches))

# Exact names used by this harness, including its historical LAN container.
OWN_CONTAINERS = {'fpe-image-build', 'fpe-ctl', 'fpe-cli', 'fpe-exit', 'fpe-intra', 'fpe-lan', 'fpe-wanprobe'}
OWN_NETWORKS = {'fpe-wan', 'fpe-mesh', 'fpe-lan'}

def reclaim_kept():
    # Never use global prune or substring matches. Foreign names and image tags
    # are retained, including names merely containing the fpe- substring.
    existing = need(P + ['ps', '-a', '--format', '{{.Names}}']).splitlines()
    nets = need(P + ['network', 'ls', '--format', '{{.Name}}']).splitlines()
    unknown = [n for n in existing if n.startswith('fpe-') and n not in OWN_CONTAINERS]
    unknown += [n for n in nets if n.startswith('fpe-') and n not in OWN_NETWORKS]
    if unknown: raise RuntimeError('unknown fpe- resources; refusing cleanup: ' + repr(unknown))
    for name in sorted(set(existing) & OWN_CONTAINERS):
        need(P + ['rm', '-f', '-t', '0', name])
    for name in sorted(set(nets) & OWN_NETWORKS):
        need(P + ['network', 'rm', name])
    images = need(P + ['images', '--format', '{{.Repository}}:{{.Tag}}']).splitlines()
    if IMAGE in images: need(P + ['rmi', IMAGE])

def interrupted(sig, frame): raise KeyboardInterrupt(f'signal {sig}')
signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
host_snapshot('before-reclaim')
reclaim_kept()
before = host_snapshot('before')
exit_code = 0
try:
    inspect = json.loads(need(P + ['network', 'inspect'] + need(P + ['network', 'ls', '-q']).split()))
    (OUT / 'existing-networks.json').write_text(json.dumps(inspect, indent=2))
    occupied = [ipaddress.ip_network(s['subnet']) for n in inspect for s in n.get('subnets', [])]
    occupied += [ipaddress.ip_network(x) for x in ('10.88.0.0/16', '10.72.0.0/24', '192.168.31.0/24', '192.168.122.0/24')]
    for r in json.loads(need(['ip', '-j', '-4', 'route'])):
        if r.get('dst') not in (None, 'default'): occupied.append(ipaddress.ip_network(r['dst'], strict=False))
    # Pick an unused /22, with independent /24 WAN, mesh and LAN segments.
    for octet in range(231, 250):
        candidate = [ipaddress.ip_network(f'10.{octet}.{n}.0/24') for n in range(3)]
        if not any(a.overlaps(b) for a in candidate for b in occupied): break
    else: raise RuntimeError('no unused candidate subnet block')
    WAN, MESH, LAN = [str(x.network_address).rsplit('.', 1)[0] for x in candidate]
    (OUT / 'topology.json').write_text(json.dumps(dict(wan=WAN, mesh=MESH, lan=LAN,
        binary_sha256=hashlib.sha256(BIN.read_bytes()).hexdigest(),
        binary_size=BIN.stat().st_size, binary_path=str(BIN), privileged=['fpe-exit'],
        scaffold='client physical-output guard + unreachable bootstrap default; exit LAN forwarding initially 1'), indent=2))
    print('SUBNETS', WAN, MESH, LAN, flush=True)
    need(P + ['image', 'exists', BASE])
    # Rootful slirp avoids activating or modifying the existing default bridge.
    containers.append('fpe-image-build')
    record('image-packages', P + ['run', '--pull=never', '--name', 'fpe-image-build', '--network', 'slirp4netns', BASE,
        'sh', '-ec', 'apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends '
        'iproute2 nftables iptables curl dnsutils iputils-ping ca-certificates jq python3 '
        '&& rm -rf /var/lib/apt/lists/*'], timeout=600)
    # Check package installation explicitly; never commit a failed setup.
    code = int(json.loads(need(P + ['inspect', 'fpe-image-build']))[0]['State']['ExitCode'])
    if code: raise RuntimeError(f'package setup failed: {code}')
    need(P + ['commit', 'fpe-image-build', IMAGE], timeout=120); image_created = True
    need(P + ['rm', 'fpe-image-build']); containers.remove('fpe-image-build')
    for name, subnet, internal in [('fpe-wan', WAN, False), ('fpe-mesh', MESH, True), ('fpe-lan', LAN, True)]:
        args = P + ['network', 'create', '--disable-dns', '--interface-name', name, '--subnet', subnet + '.0/24']
        if internal: args += ['--internal']
        networks.append(name); need(args + [name])
    for c, nets, privileged in [
        ('fpe-ctl', [(MESH, 'fpe-mesh', 10)], False),
        ('fpe-cli', [(MESH, 'fpe-mesh', 30)], False),
        ('fpe-exit', [(WAN, 'fpe-wan', 20), (MESH, 'fpe-mesh', 20), (LAN, 'fpe-lan', 20)], True),
        ('fpe-intra', [(LAN, 'fpe-lan', 40)], False)]:
        args = P + ['run', '-d', '--pull=never', '--name', c, '--hostname', c]
        for subnet, name, last in nets: args += ['--network', f'{name}:ip={subnet}.{last}']
        if privileged: args += ['--privileged']
        else:
            if c in ('fpe-cli', 'fpe-intra'): args += ['--cap-add', 'NET_ADMIN']
            if c == 'fpe-cli': args += ['--device', '/dev/net/tun']
        # The task's minimal package list does not include procps. Reuse only the
        # host's sysctl executable (libc-only), read-only, inside the exit netns.
        if c == 'fpe-exit': args += ['-v', '/usr/sbin/sysctl:/usr/sbin/sysctl:ro']
        args += ['-v', f'{BIN}:/usr/local/bin/fluxpeer:ro', IMAGE, 'sleep', 'infinity']
        containers.append(c); need(args)
        need(px(c, 'mkdir', '-p', '/run/fpe'))
    need(px('fpe-intra', 'ip', 'route', 'replace', 'default', 'via', f'{LAN}.20'))
    need(px('fpe-cli', 'ip', 'route', 'replace', 'default', 'via', f'{MESH}.1'))
    need(P + ['exec', '-i', 'fpe-cli', 'nft', '-f', '-'], 'table inet fpe_guard { chain output { type filter hook output priority -50; '
         f'policy accept; oifname "lo" accept; oifname "fpe0" accept; ip daddr {MESH}.0/24 accept; '
         'counter drop comment "fpe-no-physical-public-bypass";\n }\n}\n')
    write_container('fpe-cli', '/run/fpe/resolv.original', need(px('fpe-cli', 'cat', '/etc/resolv.conf')))
    write_container('fpe-cli', '/etc/resolv.conf', 'nameserver 1.1.1.1\noptions timeout:2 attempts:1\n')
    need(P + ['exec', '-d', 'fpe-ctl', 'sh', '-c', f'exec env FLUXPEER_ADMIN_PASSWORD={ADMIN} '
        'FLUXPEER_CONTROL_ADDR=0.0.0.0:18080 DATABASE_URL="sqlite:///run/fpe/db.sqlite?mode=rwc" '
        'RUST_LOG=info fluxpeer control > /run/fpe/control.log 2>&1'])
    need(P + ['exec', '-d', 'fpe-ctl', 'sh', '-c', 'exec env FLUXPEER_RELAY_ADDR=0.0.0.0:13478 '
        'FLUXPEER_RELAY_ANYTLS_ADDR=0.0.0.0:13443 FLUXPEER_RELAY_BOND_ADDR=0.0.0.0:13479 '
        'FLUXPEER_RELAY_NODE_ID=fluxpeer-relay RUST_LOG=info fluxpeer relay > /run/fpe/relay.log 2>&1'])
    for i in range(30):
        if run(px('fpe-ctl', 'curl', '-fsS', 'http://127.0.0.1:18080/api/v1/health'))[0] == 0: break
        time.sleep(1)
    else: raise RuntimeError('control startup failed')
    new_network('initial')

    def s0():
        check('control-reachable', px('fpe-cli', 'curl', '-fsS', f'http://{MESH}.10:18080/api/v1/health'))
        public_probe('no-direct-public-ping', targets=('1.1.1.1', '1.0.0.1'), kind='ping', success=False)
        public_probe('no-direct-public-https', success=False, max_time=5)
        check('no-intranet-bypass', px('fpe-cli', 'ping', '-c', '1', '-W', '2', f'{LAN}.40'), False)
        public_probe('exit-has-public', 'fpe-exit', max_time=10)
        capture()
    scenario('S0', s0)
    # S1 (AD-1+AD-2): only the admin's 0.0.0.0/0 approval (no exit_node flag on the
    # exit) + the client's `use_exit=auto` opt-in → full-tunnel internet works.
    def wan_probe():
        cli_cfg = api('GET', f'/devices/{state["c"]["device_id"]}/config', token=state['c']['auth_token'])
        # All lifecycle cleanup is scoped to the probe created by this run.
        containers.append('fpe-wanprobe')
        try:
            need(P + ['run', '-d', '--pull=never', '--cap-add', 'NET_ADMIN', '--name', 'fpe-wanprobe',
                      '--network', 'fpe-wan', IMAGE, 'sleep', 'infinity'])
            need(px('fpe-wanprobe', 'ip', 'route', 'add', cli_cfg['address_v4'] + '/32', 'via', WAN + '.20'))
            check('wan-probe-reaches-exit', px('fpe-wanprobe', 'ping', '-c', '2', '-W', '2', WAN + '.20'))
            check('wan-new-conn-to-client-overlay-rejected',
                  px('fpe-wanprobe', 'ping', '-c', '2', '-W', '2', cli_cfg['address_v4']), False)
            # The guard is limited to WAN; initiating from routed LAN still works.
            check('lan-new-conn-to-client-overlay', px('fpe-intra', 'ping', '-c', '2', '-W', '2', cli_cfg['address_v4']))
            capture('after-wan-probe')
        finally:
            need(P + ['rm', '-f', '-t', '0', 'fpe-wanprobe'])
            containers.remove('fpe-wanprobe')
    scenario('S1', lambda: (pair(), probes(True), wan_probe()))
    # S1-split (AD-2): same approved exit, but the client never opted in → default
    # prefixes are stripped; overlay/intranet work, public does NOT (split-tunnel).
    def s1split():
        pair(use_exit=None)
        probes(False)
        check('split-no-v4-default-halves', px('fpe-cli', 'sh', '-ec',
            '! ip -4 route show | grep -Eq "^(0.0.0.0/1|128.0.0.0/1).*dev fpe0"'))
        check('split-no-cryptokey-default', px('fpe-cli', 'sh', '-ec',
            "fluxpeer show --json | jq -se 'length > 0 and ([.[].peers[].allowed_ips[] | select(. == \"0.0.0.0/0\" or . == \"::/0\")] | length == 0)'"))
    scenario('S1-split', s1split)
    def s1off():
        need(px('fpe-exit', 'sysctl', '-w', 'net.ipv4.ip_forward=0'))
        exit_cfg = api('GET', f'/devices/{state["e"]["device_id"]}/config', token=state['e']['auth_token'])
        check('overlay-still-works', px('fpe-cli', 'ping', '-c', '2', '-W', '2', exit_cfg['address_v4']))
        check('lan-needs-forwarding', px('fpe-cli', 'ping', '-c', '2', '-W', '2', f'{LAN}.40'), False)
        capture()
    scenario('S1-forward-off', s1off)
    # S2 (AD-1 legacy override): `exit_node: true` forces the provider side on even
    # without relying on self_exit — the old local flag keeps working.
    scenario('S2', lambda: (pair(force_exit=True), probes(True)))
    def s3():
        api('DELETE', f'/routes/{state["default_route"]}')
        pair(); probes(False)
    scenario('S3', s3)
    def s4():
        state['default_route'] = route('0.0.0.0/0')
        pair()
        need(P + ['exec', '-i', 'fpe-exit', 'nft', '-f', '-'], 'table inet fpe_drop { chain forward { '
             'type filter hook forward priority 10; policy drop; counter drop comment "fpe-simulated-fw4-drop";\n }\n}\n')
        # The independent drop blocks LAN forwarding too; overlay remains local.
        public_probe('public-blocked', success=False, max_time=5)
        check('lan-blocked', px('fpe-cli', 'ping', '-c', '1', '-W', '2', f'{LAN}.40'), False)
        capture()
        need(px('fpe-exit', 'nft', 'delete', 'table', 'inet', 'fpe_drop'))
    scenario('S4', s4)
    for label, mode, directory, positive in [
        ('direct-udp', 'direct', None, True), ('relay-tcp', 'tcp', None, True),
        ('relay-anytls-explicit', 'anytls', None, True), ('relay-bond', 'bond', None, True),
        ('relay-tcp-directory', 'directory-tcp', 'tcp', True),
        ('relay-anytls-directory', 'directory-anytls', 'anytls', True)]:
        def test_transport(label=label, mode=mode, directory=directory, positive=positive):
            new_network(label, directory); pair(transport=mode); probes(positive, positive)
        scenario('S5-' + label, test_transport)

    def s6():
        new_network('race'); pair()
        probes(True)
        for i in range(3):
            api('DELETE', f'/routes/{state["default_route"]}')
            time.sleep(3)
            record(f'race-{i}-before-route', px('fpe-cli', 'ip', 'route'))
            stop('fpe-exit')
            port = 41842 + i
            e, unused = settings(port=port)
            started = time.monotonic()
            start('fpe-exit', e)
            endpoints(state['e'], f'{MESH}.20', port)
            state['default_route'] = route('0.0.0.0/0')
            elapsed = time.monotonic() - started
            time.sleep(5)
            rc, replies, evidence = public_probe(f'race-{i}-public', max_time=6, judge=False)
            rr = record(f'race-{i}-route', px('fpe-cli', 'ip', 'route'))
            suspected = '0.0.0.0/1' in rr[1] and rc != 0
            observations.append(dict(scenario='S6', attempt=i, restart_to_approve_s=elapsed,
                within_2s=elapsed < 2, public_rc=rc, split_default_present='0.0.0.0/1' in rr[1],
                f09_candidate=suspected, note='candidate requires matching reconcile log; not unique proof'))
            capture(f'race-{i}')
            # Rebuild the client from the same config to measure restart recovery.
            stop('fpe-cli'); start('fpe-cli', settings(port=port)[1]); time.sleep(8)
            public_probe(f'race-{i}-client-restart-recovery')
        capture()
    scenario('S6', s6)
    def s7():
        new_network('dns'); pair(dns=False)
        original = need(px('fpe-cli', 'cat', '/run/fpe/resolv.original'))
        write_container('fpe-cli', '/etc/resolv.conf', original)
        capture('without-dns-override')
        public_probe('original-resolver-query', targets=('example.com', 'www.cloudflare.com'), kind='dns', judge=False)
        public_probe('original-resolver-https', targets=DNS_TARGETS, max_time=10, judge=False)
        # Restart with an explicit reachable resolver, then measure restoration.
        pair(dns=True)
        public_probe('configured-resolver-query', targets=('example.com', 'www.cloudflare.com'), kind='dns')
        public_probe('configured-resolver-https', targets=DNS_TARGETS, max_time=10)
        capture('configured')
        stop('fpe-cli')
        rc, out, err, name = record('resolver-after-stop', px('fpe-cli', 'cat', '/etc/resolv.conf'))
        observations.append(dict(scenario='S7', original=original, after_stop=out,
            original_restored=out == original, evidence=name))
        require_observation('original-resolver-restored', rc == 0 and out == original, name)
    scenario('S7', s7)
    scenario('S8-dns-bind-mount', lambda: dns_lifecycle(False))
    scenario('S9-dns-dead-owner', lambda: dns_lifecycle(True))
    def sysctl_failure():
        # Deliberately fail the real sysctl command without modifying its binary
        # or node sources. This bind mount is private to the exit container.
        new_network('sysctl-failure'); stop_pair()
        need(px('fpe-exit', 'sysctl', '-w', 'net.ipv4.ip_forward=0'))
        need(px('fpe-exit', 'mount', '--bind', '/proc/sys', '/proc/sys'))
        need(px('fpe-exit', 'mount', '-o', 'remount,bind,ro', '/proc/sys'))
        try:
            e, c = settings()
            start('fpe-exit', e); start('fpe-cli', c); time.sleep(10)
            observe_counters()
            check('sysctl-write-fails', px('fpe-exit', 'sysctl', '-w', 'net.ipv4.ip_forward=1'), False)
            record('private-readonly-mount', px('fpe-exit', 'sh', '-c', 'grep /proc/sys /proc/self/mountinfo'))
            cfg = api('GET', f'/devices/{state["e"]["device_id"]}/config', token=state['e']['auth_token'])
            check('overlay-works', px('fpe-cli', 'ping', '-c', '2', '-W', '2', cfg['address_v4']))
            check('forwarded-lan-blocked', px('fpe-cli', 'ping', '-c', '1', '-W', '2', f'{LAN}.40'), False)
            public_probe('public-blocked', success=False, max_time=5)
            public_probe('exit-still-has-public', 'fpe-exit', max_time=10)
            capture()
        finally:
            need(px('fpe-exit', 'mount', '-o', 'remount,bind,rw', '/proc/sys'))
            need(px('fpe-exit', 'umount', '/proc/sys'))
    scenario('S4-sysctl-failure', sysctl_failure)
except BaseException:
    exit_code = 2
    (OUT / 'setup-or-interruption-error.txt').write_text(traceback.format_exc())
    print(traceback.format_exc(), flush=True)
finally:
    try: cleanup()
    except BaseException:
        exit_code = 3
        (OUT / 'cleanup-error.txt').write_text(traceback.format_exc())
        print(traceback.format_exc(), flush=True)
    (OUT / 'checks.json').write_text(json.dumps(checks, indent=2))
    (OUT / 'observations.json').write_text(json.dumps(observations, indent=2))
    failed = [c for c in checks if c['verdict'] == 'FAIL']
    print(json.dumps(dict(evidence=str(OUT), checks=len(checks), failed=len(failed), keep=KEEP)), flush=True)
    if not exit_code and failed: exit_code = 1
sys.exit(exit_code)
PY
