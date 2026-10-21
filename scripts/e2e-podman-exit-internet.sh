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
ROOT=/opt/ops/fp/t0022
export FPE_KEEP="$KEEP" FPE_ROOT="$ROOT" FPE_FAULT_ONLY="$FAULT_ONLY"
test "$(uname -s)" = Linux
test -x "$ROOT/bin/fluxpeer"
sudo -n podman version >/dev/null
# Python owns the finally/trap equivalent, including signals and partial setup.
exec python3 - <<'PY'
import datetime, hashlib, ipaddress, json, os, pathlib, re, shlex, signal
import subprocess as sp
import sys, time, traceback

ROOT = pathlib.Path(os.environ['FPE_ROOT'])
KEEP = os.environ['FPE_KEEP'] == '1'
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
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

def start(c, cfg):
    write_container(c, '/run/fpe/node.json', json.dumps(cfg))
    # Only the process log is truncated; prior scenario snapshots remain in OUT.
    need(P + ['exec', '-d', c, 'sh', '-c', 'echo $$ > /run/fpe/node.pid; '
        'exec env RUST_LOG=info,fp_transport_anytls::health=error fluxpeer node run /run/fpe/node.json > /run/fpe/node.log 2>&1'])

def settings(exit_flag=True, transport='direct', dns=True, port=41841):
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
    e['exit_node'] = exit_flag
    c['exit_node'] = False
    return e, c

def pair(exit_flag=True, transport='direct', dns=True):
    stop_pair()
    e, c = settings(exit_flag, transport, dns)
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
            network_id=state['net'], anytls=directory == 'anytls', stun_url=f'{MESH}.10:13478'))

def observe_counters():
    # Counter-only rules observe traversal; they do not accept/drop/masquerade.
    phys = json.loads(need(px('fpe-exit', 'ip', '-j', 'route', 'show', 'default')))[0]['dev']
    record('observe-forward-counter', px('fpe-exit', 'nft', 'insert', 'rule', 'inet', 'fluxpeer', 'forward',
           'iifname', 'fpe0', 'counter', 'comment', '"fpe-observe-forward"'))
    record('observe-nat-counter', px('fpe-exit', 'nft', 'insert', 'rule', 'inet', 'fluxpeer', 'postrouting',
           'oifname', phys, 'counter', 'comment', '"fpe-observe-nat"'))

def capture(label='after'):
    if 'c' in state:
        cfg = api('GET', f'/devices/{state["c"]["device_id"]}/config', token=state['c']['auth_token'])
        (OUT / f'{group}-{label}-client-config.json').write_text(json.dumps(cfg, indent=2))
    cmds = [
        ('client-route', px('fpe-cli', 'ip', 'route')),
        ('client-route-get', px('fpe-cli', 'ip', 'route', 'get', '1.1.1.1')),
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
    check('public-ip-https', px('fpe-cli', 'curl', '--noproxy', '*', '-fsS', '--max-time', '8',
                               '-o', '/dev/null', '-w', 'HTTP=%{http_code} REMOTE=%{remote_ip}\n', 'https://1.1.1.1'), positive)
    check('public-dns-https', px('fpe-cli', 'curl', '--noproxy', '*', '-fsS', '--max-time', '10',
                                '-o', '/dev/null', '-w', 'HTTP=%{http_code} REMOTE=%{remote_ip}\n', 'https://example.com'), positive)
    check('dns-query', px('fpe-cli', 'dig', '+time=2', '+tries=1', 'example.com', 'A'), positive)
    a = record('exit-source-ip', px('fpe-exit', 'curl', '--noproxy', '*', '-fsS', '--max-time', '10',
                                   'https://1.1.1.1/cdn-cgi/trace'))
    b = record('client-source-ip', px('fpe-cli', 'curl', '--noproxy', '*', '-fsS', '--max-time', '8',
                                     'https://1.1.1.1/cdn-cgi/trace'))
    ips = lambda text: re.findall(r'^ip=(.+)$', text, re.M)
    same = a[0] == b[0] == 0 and bool(ips(a[1])) and ips(a[1]) == ips(b[1])
    checks.append(dict(scenario=group, check='egress-source-match', expected_rc='match' if positive else 'no successful client request',
        actual_rc=0 if same else 1, verdict='PASS' if (same if positive else b[0] != 0) else 'FAIL', evidence=[a[3], b[3]]))
    print(f'{group} egress-source-match: {"MATCH" if same else "NO_MATCH"}', flush=True)
    capture()

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
        matches = [x for x in out.splitlines() if 'fpe-' in x]
        checks.append(dict(scenario='cleanup', check='no-fpe-' + label, actual_rc=rc,
                           verdict='PASS' if rc == 0 and not matches else 'FAIL', evidence=fname, remaining=matches))

def interrupted(sig, frame): raise KeyboardInterrupt(f'signal {sig}')
signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
before = host_snapshot('before')
exit_code = 0
try:
    # Refuse preexisting resources instead of deleting another invocation's work.
    if any('fpe-' in before[k] for k in ('containers', 'networks', 'images')):
        raise RuntimeError('preexisting fpe- resources; refusing to reuse/remove them')
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
        binary_sha256=hashlib.sha256((ROOT/'bin/fluxpeer').read_bytes()).hexdigest(),
        binary_size=(ROOT/'bin/fluxpeer').stat().st_size, privileged=['fpe-exit'],
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
        args += ['-v', f'{ROOT}/bin/fluxpeer:/usr/local/bin/fluxpeer:ro', IMAGE, 'sleep', 'infinity']
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
        check('no-direct-public-ping', px('fpe-cli', 'ping', '-c', '1', '-W', '2', '1.1.1.1'), False)
        check('no-direct-public-https', px('fpe-cli', 'curl', '--noproxy', '*', '-fsS', '--max-time', '5', 'https://1.1.1.1'), False)
        check('no-intranet-bypass', px('fpe-cli', 'ping', '-c', '1', '-W', '2', f'{LAN}.40'), False)
        check('exit-has-public', px('fpe-exit', 'curl', '--noproxy', '*', '-fsS', '--max-time', '10', 'https://1.1.1.1/cdn-cgi/trace'))
        capture()
    scenario('S0', s0)
    scenario('S1', lambda: (pair(False), probes(False)))
    def s1off():
        need(px('fpe-exit', 'sysctl', '-w', 'net.ipv4.ip_forward=0'))
        exit_cfg = api('GET', f'/devices/{state["e"]["device_id"]}/config', token=state['e']['auth_token'])
        check('overlay-still-works', px('fpe-cli', 'ping', '-c', '2', '-W', '2', exit_cfg['address_v4']))
        check('lan-needs-forwarding', px('fpe-cli', 'ping', '-c', '2', '-W', '2', f'{LAN}.40'), False)
        capture()
    scenario('S1-forward-off', s1off)
    scenario('S2', lambda: (pair(True), probes(True)))
    def s3():
        api('DELETE', f'/routes/{state["default_route"]}')
        pair(True); probes(False)
    scenario('S3', s3)
    def s4():
        state['default_route'] = route('0.0.0.0/0')
        pair(True)
        need(P + ['exec', '-i', 'fpe-exit', 'nft', '-f', '-'], 'table inet fpe_drop { chain forward { '
             'type filter hook forward priority 10; policy drop; counter drop comment "fpe-simulated-fw4-drop";\n }\n}\n')
        # The independent drop blocks LAN forwarding too; overlay remains local.
        check('public-blocked', px('fpe-cli', 'curl', '--noproxy', '*', '-fsS', '--max-time', '5', 'https://1.1.1.1'), False)
        check('lan-blocked', px('fpe-cli', 'ping', '-c', '1', '-W', '2', f'{LAN}.40'), False)
        capture()
        need(px('fpe-exit', 'nft', 'delete', 'table', 'inet', 'fpe_drop'))
    scenario('S4', s4)
    for label, mode, directory, positive in [
        ('direct-udp', 'direct', None, True), ('relay-tcp', 'tcp', None, True),
        ('relay-anytls-explicit', 'anytls', None, True), ('relay-bond', 'bond', None, True),
        ('relay-tcp-directory', 'directory-tcp', 'tcp', True),
        ('relay-anytls-directory', 'directory-anytls', 'anytls', False)]:
        def test_transport(label=label, mode=mode, directory=directory, positive=positive):
            new_network(label, directory); pair(True, mode); probes(positive, positive)
        scenario('S5-' + label, test_transport)

    def s6():
        new_network('race'); pair(True)
        probes(True)
        for i in range(3):
            api('DELETE', f'/routes/{state["default_route"]}')
            time.sleep(3)
            record(f'race-{i}-before-route', px('fpe-cli', 'ip', 'route'))
            stop('fpe-exit')
            port = 41842 + i
            e, unused = settings(True, port=port)
            started = time.monotonic()
            start('fpe-exit', e)
            endpoints(state['e'], f'{MESH}.20', port)
            state['default_route'] = route('0.0.0.0/0')
            elapsed = time.monotonic() - started
            time.sleep(5)
            rc, out, err, name = record(f'race-{i}-public', px('fpe-cli', 'curl', '--noproxy', '*', '-fsS', '--max-time', '6', 'https://1.1.1.1/cdn-cgi/trace'))
            rr = record(f'race-{i}-route', px('fpe-cli', 'ip', 'route'))
            suspected = '0.0.0.0/1' in rr[1] and rc != 0
            observations.append(dict(scenario='S6', attempt=i, restart_to_approve_s=elapsed,
                within_2s=elapsed < 2, public_rc=rc, split_default_present='0.0.0.0/1' in rr[1],
                f09_candidate=suspected, note='candidate requires matching reconcile log; not unique proof'))
            capture(f'race-{i}')
            # Rebuild the client from the same config to measure restart recovery.
            stop('fpe-cli'); start('fpe-cli', settings(True, port=port)[1]); time.sleep(8)
            check(f'race-{i}-client-restart-recovery', px('fpe-cli', 'curl', '--noproxy', '*', '-fsS', '--max-time', '8', 'https://1.1.1.1/cdn-cgi/trace'))
        capture()
    scenario('S6', s6)
    def s7():
        new_network('dns'); pair(True, dns=False)
        original = need(px('fpe-cli', 'cat', '/run/fpe/resolv.original'))
        write_container('fpe-cli', '/etc/resolv.conf', original)
        capture('without-dns-override')
        record('original-resolver-query', px('fpe-cli', 'dig', '+time=2', '+tries=1', 'example.com', 'A'))
        record('original-resolver-https', px('fpe-cli', 'curl', '--noproxy', '*', '-fsS', '--max-time', '10', 'https://example.com'))
        # Restart with an explicit reachable resolver, then measure restoration.
        pair(True, dns=True)
        check('configured-resolver-query', px('fpe-cli', 'dig', '+time=2', '+tries=1', 'example.com', 'A'))
        check('configured-resolver-https', px('fpe-cli', 'curl', '--noproxy', '*', '-fsS', '--max-time', '10', 'https://example.com'))
        capture('configured')
        stop('fpe-cli')
        rc, out, err, name = record('resolver-after-stop', px('fpe-cli', 'cat', '/etc/resolv.conf'))
        observations.append(dict(scenario='S7', original=original, after_stop=out,
            original_restored=out == original, evidence=name))
    scenario('S7', s7)
    def sysctl_failure():
        # Deliberately fail the real sysctl command without modifying its binary
        # or node sources. This bind mount is private to the exit container.
        new_network('sysctl-failure'); stop_pair()
        need(px('fpe-exit', 'sysctl', '-w', 'net.ipv4.ip_forward=0'))
        need(px('fpe-exit', 'mount', '--bind', '/proc/sys', '/proc/sys'))
        need(px('fpe-exit', 'mount', '-o', 'remount,bind,ro', '/proc/sys'))
        try:
            e, c = settings(True)
            start('fpe-exit', e); start('fpe-cli', c); time.sleep(10)
            observe_counters()
            check('sysctl-write-fails', px('fpe-exit', 'sysctl', '-w', 'net.ipv4.ip_forward=1'), False)
            record('private-readonly-mount', px('fpe-exit', 'sh', '-c', 'grep /proc/sys /proc/self/mountinfo'))
            cfg = api('GET', f'/devices/{state["e"]["device_id"]}/config', token=state['e']['auth_token'])
            check('overlay-works', px('fpe-cli', 'ping', '-c', '2', '-W', '2', cfg['address_v4']))
            check('forwarded-lan-blocked', px('fpe-cli', 'ping', '-c', '1', '-W', '2', f'{LAN}.40'), False)
            check('public-blocked', px('fpe-cli', 'curl', '--noproxy', '*', '-fsS', '--max-time', '5', 'https://1.1.1.1'), False)
            record('exit-still-has-public', px('fpe-exit', 'curl', '--noproxy', '*', '-fsS', '--max-time', '10', 'https://1.1.1.1/cdn-cgi/trace'))
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
