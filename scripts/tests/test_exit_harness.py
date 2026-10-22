# SPDX-License-Identifier: BSD-3-Clause
"""Run the real harness helpers with fake commands; never create host resources."""
import ast
import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import shlex
import tempfile
import unittest
from unittest.mock import Mock

SCRIPT = Path(__file__).resolve().parents[1] / 'e2e-podman-exit-internet.sh'
SOURCE = SCRIPT.read_text()
INLINE = SOURCE.split("exec python3 - <<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
TREE = ast.parse(INLINE, filename=str(SCRIPT))


def helpers():
    constants = {'PUBLIC_TARGETS', 'DNS_TARGETS', 'TRACE_TARGETS', 'OWN_CONTAINERS', 'OWN_NETWORKS'}
    nodes = [n for n in TREE.body if isinstance(n, ast.FunctionDef) or
             isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in n.targets)]
    ns = dict(json=json, re=re, checks=[], observations=[], group='test', P=['podman'],
              ADMIN='test-only', IMAGE='localhost/fpe-node:t0022', probe_ports=list(range(20000, 20100)),
              time=Mock(), state={}, os=os, sp=subprocess, shlex=shlex)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(SCRIPT), 'exec'), ns)
    return ns


class PublicProbes(unittest.TestCase):
    def setUp(self):
        self.ns = helpers()
        self.outputs = []
        self.calls = []
        def record(label, args, **kwargs):
            self.calls.append(args)
            rc, body = self.outputs.pop(0)
            return rc, body, '', f'evidence-{len(self.calls)}'
        self.ns['record'] = record

    def probe(self, outputs, **kwargs):
        self.outputs = list(outputs)
        with contextlib.redirect_stdout(io.StringIO()):
            return self.ns['public_probe']('public', **kwargs)

    def test_retry_once_new_port_and_keep_both_results(self):
        rc, replies, evidence = self.probe([(28, ''), (0, 'ok'), (0, 'ok')])
        self.assertEqual(rc, 0)
        self.assertEqual(len(replies), 2)
        self.assertEqual(len(evidence), 3)
        ports = [a[a.index('--local-port') + 1] for a in self.calls]
        self.assertEqual(len(set(ports)), 3)
        self.assertEqual(self.calls[0][-1], self.calls[1][-1])
        self.assertNotEqual(self.calls[1][-1], self.calls[2][-1])
        self.assertEqual([a['actual_rc'] for a in self.ns['checks'][0]['attempts']], [28, 0, 0])

    def test_other_target_success_survives_two_timeouts(self):
        self.probe([(28, ''), (28, ''), (0, 'ok')])
        self.assertEqual(self.ns['checks'][0]['verdict'], 'PASS')

    def test_all_targets_fail_after_exactly_one_retry(self):
        self.probe([(28, '')] * 4)
        self.assertEqual(len(self.calls), 4)
        self.assertEqual(self.ns['checks'][0]['verdict'], 'FAIL')

    def test_negative_check_fails_if_any_target_leaks(self):
        self.probe([(28, ''), (28, ''), (0, 'leak')], success=False)
        self.assertEqual(self.ns['checks'][0]['verdict'], 'FAIL')

    def test_negative_check_passes_only_if_all_blocked(self):
        self.probe([(28, '')] * 4, success=False)
        self.assertEqual(self.ns['checks'][0]['verdict'], 'PASS')

    def test_empty_dns_answer_is_not_success(self):
        self.probe([(0, '')] * 4, targets=('example.com', 'www.cloudflare.com'), kind='dns')
        self.assertEqual(self.ns['checks'][0]['verdict'], 'FAIL')

    def test_observation_records_without_changing_verdicts(self):
        self.probe([(28, '')] * 4, judge=False)
        self.assertFalse(self.ns['checks'])
        self.assertEqual(len(self.ns['observations'][0]['attempts']), 4)

    def test_egress_mismatch_not_hidden_by_another_match(self):
        self.outputs = [(0, 'ip=192.0.2.1\n'), (0, 'ip=192.0.2.1\n'),
                        (0, 'ip=192.0.2.2\n'), (0, 'ip=192.0.2.1\n')]
        self.ns['egress_probe'](True)
        self.assertEqual(self.ns['checks'][0]['verdict'], 'FAIL')
        self.assertEqual(len(self.ns['checks'][0]['invalid']), 1)

    def test_egress_other_target_can_match_after_timeout(self):
        self.outputs = [(28, ''), (28, ''), (0, 'ip=192.0.2.1\n'),
                        (28, ''), (28, ''), (0, 'ip=192.0.2.1\n')]
        self.ns['egress_probe'](True)
        self.assertEqual(self.ns['checks'][0]['verdict'], 'PASS')

    def test_reject_single_target(self):
        with self.assertRaises(ValueError): self.probe([], targets=('https://1.1.1.1',))


class ReclaimKept(unittest.TestCase):
    def setUp(self):
        self.ns = helpers()
        self.calls = []
        self.containers = 'fpe-cli\nunrelated-fpe-cli\nproduction\n'
        self.networks = 'fpe-mesh\nproduction-net\n'
        def need(args):
            self.calls.append(args)
            if args[1] == 'ps': return self.containers
            if args[1:3] == ['network', 'ls']: return self.networks
            if args[1] == 'images': return 'localhost/fpe-node:t0022\nlocalhost/fpe-node:foreign\n'
            return ''
        self.ns['need'] = need

    def test_only_exact_owned_resources_removed(self):
        self.ns['reclaim_kept']()
        mutations = [a for a in self.calls if a[1] in ('rm', 'rmi') or a[1:3] == ['network', 'rm']]
        self.assertEqual(mutations, [['podman', 'rm', '-f', '-t', '0', 'fpe-cli'],
                                   ['podman', 'network', 'rm', 'fpe-mesh'],
                                   ['podman', 'rmi', 'localhost/fpe-node:t0022']])

    def test_unknown_prefixed_resource_aborts_before_any_deletion(self):
        for resource in ('container', 'network'):
            with self.subTest(resource=resource):
                self.setUp()
                if resource == 'container': self.containers += 'fpe-foreign\n'
                else: self.networks += 'fpe-foreign\n'
                with self.assertRaisesRegex(RuntimeError, 'unknown fpe-'): self.ns['reclaim_kept']()
                self.assertEqual(len(self.calls), 2)

    def test_cleanup_failure_propagates(self):
        self.ns['need'] = Mock(side_effect=['fpe-cli', 'fpe-mesh', RuntimeError('busy')])
        with self.assertRaisesRegex(RuntimeError, 'busy'): self.ns['reclaim_kept']()


class DnsAssertions(unittest.TestCase):
    def setUp(self): self.ns = helpers()

    def test_wrong_restore_fails_with_actual_evidence(self):
        self.ns['run'] = Mock(return_value=(0, 'dead owner DNS', ''))
        self.ns['record'] = Mock(return_value=(0, 'dead owner DNS', '', 'actual-resolver'))
        with self.assertRaisesRegex(RuntimeError, 'baseline-restored'):
            self.ns['expect_dns']('baseline-restored', 'original DNS')
        self.assertEqual(self.ns['checks'][0]['verdict'], 'FAIL')
        self.assertEqual(self.ns['checks'][0]['evidence'], 'actual-resolver')

    def test_normal_and_crash_lifecycle_assert_before_cleanup(self):
        for crash in (False, True):
            with self.subTest(crash=crash):
                self.setUp()
                events = []
                for name in ('new_network', 'stop_pair', 'check', 'stop'):
                    self.ns[name] = Mock()
                self.ns['settings'] = lambda: ({}, {'tun_name': 'fpe0'})
                self.ns['start'] = lambda c, cfg, **kw: events.append(('start', c, dict(cfg), kw))
                self.ns['expect_dns'] = lambda label, expected: events.append(('expect', label, expected))
                self.ns['write_container'] = lambda c, path, text: events.append(('write', text))
                commands = []
                def need(args):
                    commands.append(args)
                    if 'cat' in args: return 'original resolver'
                    if '-j' in args: return '{"nftables": []}'
                    return ''
                self.ns['need'] = need
                journals = {'first-dns-journal': ['fpe0'], 'second-dns-journal': ['fpe1'], 'dns-journal-after-stop': []}
                def record(label, args):
                    if label == 'resolver-mountinfo': body = '1 2 0:3 /file /etc/resolv.conf rw - tmpfs tmpfs rw'
                    else: body = json.dumps({'owners': [{'iface': f} for f in journals[label]]})
                    return 0, body, '', label
                self.ns['record'] = record
                self.ns['dns_lifecycle'](crash)
                self.assertEqual(events[-1], ('write', 'original resolver'))
                self.assertEqual(events[-2][1], 'baseline-restored-after-stop')
                self.assertIn('192.0.2.53', events[-2][2])
                self.assertTrue(all(c['verdict'] == 'PASS' for c in self.ns['checks']))
                if crash:
                    self.assertTrue(any('kill -KILL' in ' '.join(c) for c in commands))
                    self.assertTrue(any(e[0] == 'start' and e[2].get('tun_name') == 'fpe1' for e in events))
                    self.assertIn('dead-owner-pruned', [c['check'] for c in self.ns['checks']])


class ShellAndScope(unittest.TestCase):
    def test_shell_syntax(self): subprocess.run(['bash', '-n', str(SCRIPT)], check=True)

    def test_root_and_binary_defaults_and_overrides(self):
        prefix = SOURCE.split('test "$(uname -s)"', 1)[0]
        for overrides, expected in [({}, '/opt/ops/fp/e2e\n/opt/ops/fp/e2e/bin/fluxpeer'),
                                    ({'FLUXPEER_E2E_ROOT': '/tmp/root with spaces'}, '/tmp/root with spaces\n/tmp/root with spaces/bin/fluxpeer'),
                                    ({'FLUXPEER_E2E_ROOT': '/tmp/root', 'FLUXPEER_BIN': '/tmp/other binary'}, '/tmp/root\n/tmp/other binary')]:
            env = {k: v for k, v in os.environ.items() if k not in ('FLUXPEER_BIN', 'FLUXPEER_E2E_ROOT')}
            env.update(overrides)
            out = subprocess.check_output(['bash', '-c', prefix + '\nprintf "%s\\n%s" "$ROOT" "$BIN"'], env=env, text=True)
            self.assertEqual(out, expected)

    def test_no_single_target_public_curl_call_sites_remain(self):
        # Public curl commands must go through public_probe, not record/check.
        for node in ast.walk(TREE):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'px':
                literals = [a.value for a in node.args if isinstance(a, ast.Constant)]
                if 'curl' in literals:
                    self.assertFalse(any(isinstance(v, str) and v.startswith('https://') for v in literals))


class RelayIdentity(unittest.TestCase):
    def test_provision_and_start_use_same_key_path(self):
        ns = helpers()
        ns['need'] = Mock(side_effect=['ab' * 32 + '\n', ''])
        self.assertEqual(ns['start_relay'](), 'ab' * 32)
        provision, start = [c.args[0] for c in ns['need'].call_args_list]
        self.assertEqual(provision, ['podman', 'exec', 'fpe-ctl', 'fluxpeer', 'relay',
                                    'public-key', '--key-file', '/run/fpe/relay/relay.key'])
        self.assertIn('FLUXPEER_RELAY_KEY_FILE=' + provision[-1] + ' ', start[-1])
        self.assertIn('fluxpeer relay >', start[-1])

    def test_bad_key_stops_before_starting_relay(self):
        ns = helpers()
        for value in ('', 'legacy binary help', 'ab' * 31):
            ns['need'] = Mock(return_value=value)
            with self.assertRaises(RuntimeError): ns['start_relay']()
            self.assertEqual(ns['need'].call_count, 1)

    def test_pin_survives_network_reset_and_reaches_every_relay_path(self):
        ns = helpers()
        pin = 'cd' * 32
        ns.update(MESH='192.0.2', LAN='198.51.100', relay_public_key=pin)
        ns['stop_pair'] = Mock()
        ns['enroll'] = Mock(return_value={})
        ns['endpoints'] = Mock()
        ns['route'] = Mock()
        ns['api'] = Mock(return_value={'id': 'test-network'})
        for carrier in ('tcp', 'anytls'):
            ns['new_network']('test', directory=carrier)
            registration = ns['api'].call_args.args
            self.assertEqual(registration[:2], ('POST', '/relays'))
            self.assertEqual(registration[2]['public_key'], pin)
            self.assertEqual(registration[2]['network_id'], 'test-network')
            for transport in ('tcp', 'bond', 'anytls'):
                for cfg in ns['settings'](transport=transport):
                    self.assertEqual(cfg['relay_public_key'], pin)
                    self.assertTrue(cfg['force_relay'])
            for transport in ('direct', 'directory-tcp', 'directory-anytls'):
                for cfg in ns['settings'](transport=transport):
                    self.assertNotIn('relay_public_key', cfg)
                    self.assertNotIn('relay', cfg)


class ApiDiagnostics(unittest.TestCase):
    METRICS = '\nFPE_CURL_METRICS {"http_code":"200","time_starttransfer":0.012,"time_total":0.015}\nFPE_CURL_EXIT=0\n'

    def setUp(self):
        self.ns = helpers()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ns.update(OUT=self.root, seq=0)
        self.results = []
        self.calls = []
        def run(args, data=None, timeout=40, diagnose=True):
            self.calls.append((args, timeout))
            if 'curl' in args: return self.results.pop(0)
            return 0, 'process snapshot', ''
        self.ns['run'] = run

    def evidence(self):
        return [json.loads(p.read_text()) for p in sorted(self.root.glob('*-api-*-attempt-*.json'))]

    def test_success_records_metrics_and_uses_nested_deadlines_without_secrets(self):
        self.results = [(0, '{"token":"secret-response"}', self.METRICS)]
        result = self.ns['api']('POST', '/networks/n/invites/secret-code', {'password': 'secret-body'}, token='secret-header')
        self.assertEqual(result, {'token': 'secret-response'})
        data = self.evidence()[0]
        self.assertEqual(data['curl'], dict(http_code='200', time_starttransfer=0.012, time_total=0.015))
        self.assertEqual(data['container_exit'], 0)
        self.assertTrue(data['stdout_complete_json'])
        self.assertFalse(data['outer_timeout'])
        args, outer = self.calls[0]
        wrapper = args[args.index('-c') + 1]
        self.assertIn('timeout --signal=TERM --kill-after=2s 12s "$@"', wrapper)
        self.assertGreater(outer, 14)
        self.assertEqual(args[args.index('--max-time') + 1], '10')
        self.assertIn('%{stderr}', args[args.index('-w') + 1])
        for path in self.root.iterdir(): self.assertNotIn('secret-', path.read_text())

    def test_outer_timeout_complete_json_is_not_retried_or_relabelled_success(self):
        self.results = [(124, '{"id":"net-47"}', self.METRICS + '\nHARNESS_TIMEOUT\n')]
        with self.assertRaisesRegex(RuntimeError, 'complete_json=True'): self.ns['api']('GET', '/networks')
        data = self.evidence()[0]
        self.assertEqual(data['classification'], 'outer_timeout_complete_json')
        self.assertEqual(data['container_exit'], 0)
        self.assertFalse(data['retry'])
        self.assertEqual(len(data['snapshots']), 3)
        self.assertEqual(len(self.calls), 4)
        self.assertTrue(all(t == 3 for _, t in self.calls[1:]))
        self.assertEqual(self.calls[1][0][1:3], ['ps', '-a'])
        for args, _ in self.calls[2:]: self.assertIn('comm', args[-1])
        for name in data['snapshots']: self.assertTrue((self.root / name).exists())

    def test_get_incomplete_outer_timeout_retries_once_and_keeps_both_attempts(self):
        self.results = [(124, '{"id":', '\nHARNESS_TIMEOUT\n'), (0, '[]', self.METRICS)]
        self.assertEqual(self.ns['api']('GET', '/networks'), [])
        first, second = self.evidence()
        self.assertTrue(first['retry'])
        self.assertIn('GET outer timeout', first['retry_reason'])
        self.assertFalse(first['stdout_complete_json'])
        self.assertTrue(second['stdout_complete_json'])
        self.assertEqual(second['attempt'], 2)
        self.assertEqual(len(self.calls), 5)

    def test_second_get_timeout_is_terminal(self):
        self.results = [(124, '', '\nHARNESS_TIMEOUT\n')] * 2
        with self.assertRaises(RuntimeError): self.ns['api']('GET', '/networks')
        first, second = self.evidence()
        self.assertTrue(first['retry'])
        self.assertFalse(second['retry'])
        self.assertEqual(len(self.calls), 8)

    def test_writes_never_retry_even_if_output_is_incomplete(self):
        for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            with self.subTest(method=method):
                self.results = [(124, '', '\nHARNESS_TIMEOUT\n')]
                self.calls.clear()
                with self.assertRaises(RuntimeError): self.ns['api'](method, '/networks', {})
                self.assertEqual(len(self.calls), 4)
                self.assertFalse(self.evidence()[-1]['retry'])

    def test_curl_and_container_failures_are_not_outer_timeouts_and_do_not_retry(self):
        for rc in (22, 28, 124):
            with self.subTest(rc=rc):
                self.results = [(rc, '', f'FPE_CURL_EXIT={rc}\n')]
                self.calls.clear()
                with self.assertRaises(RuntimeError): self.ns['api']('GET', '/networks')
                self.assertEqual(len(self.calls), 1)
                self.assertFalse(self.evidence()[-1]['outer_timeout'])
                self.assertFalse(self.evidence()[-1]['retry'])

    def test_invalid_nonempty_response_fails_without_secret_in_exception(self):
        self.results = [(0, '{"secret-partial":', self.METRICS)]
        with self.assertRaises(RuntimeError) as raised: self.ns['api']('GET', '/networks')
        self.assertNotIn('secret-partial', str(raised.exception))
        self.assertEqual(len(self.calls), 1)

    def test_empty_delete_response_and_unavailable_metrics_are_preserved(self):
        self.results = [(0, '', 'FPE_CURL_METRICS incomplete\nFPE_CURL_EXIT=0\n')]
        self.assertIsNone(self.ns['api']('DELETE', '/networks/n'))
        self.assertIsNone(self.evidence()[0]['curl'])

    def test_run_preserves_partial_bytes_and_identifies_only_outer_deadline(self):
        ns = helpers()
        ns['sp'] = Mock(PIPE=subprocess.PIPE, TimeoutExpired=subprocess.TimeoutExpired)
        ns['sp'].run.side_effect = subprocess.TimeoutExpired(['fake'], 20, output=b'{"id":"n"}', stderr=b'partial')
        rc, out, err = ns['run'](['fake'], timeout=20)
        self.assertEqual((rc, out), (124, '{"id":"n"}'))
        self.assertTrue(ns['outer_timeout'](rc, err))
        ns['sp'].run.side_effect = None
        ns['sp'].run.return_value = subprocess.CompletedProcess(['fake'], 124, '', 'FPE_CURL_EXIT=124')
        rc, _, err = ns['run'](['fake'])
        self.assertFalse(ns['outer_timeout'](rc, err))


class ExecTimeoutDiagnostics(unittest.TestCase):
    def setUp(self):
        self.ns = helpers()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ns.update(OUT=self.root, seq=0)
        self.ns['sp'] = Mock(PIPE=subprocess.PIPE, TimeoutExpired=subprocess.TimeoutExpired)
        self.calls = []
        def execute(args, **kwargs):
            self.calls.append((args, kwargs))
            if args[1] == 'exec':
                raise subprocess.TimeoutExpired(args, kwargs['timeout'], output=b'{"private_key":"secret-key"}', stderr=b'secret-stderr')
            # Podman status/top can also stall during host contention.
            if args[0] == 'podman': raise subprocess.TimeoutExpired(args, kwargs['timeout'])
            return subprocess.CompletedProcess(args, 0, 'safe process snapshot', '')
        self.ns['sp'].run.side_effect = execute

    def test_cat_timeout_records_target_snapshots_even_when_podman_status_stalls(self):
        with self.assertRaises(RuntimeError) as error:
            self.ns['need'](['podman', 'exec', 'fpe-exit', 'cat', '/run/fpe/node.json'])
        self.assertIn('exec-timeout.json', str(error.exception))
        self.assertNotIn('secret-', str(error.exception))
        evidence = list(self.root.glob('*-exec-timeout.json'))
        self.assertEqual(len(evidence), 1)
        data = json.loads(evidence[0].read_text())
        self.assertEqual(data['container'], 'fpe-exit')
        self.assertTrue(data['stdout_complete_json'])
        self.assertFalse(data['retry'])
        self.assertEqual(len(data['snapshots']), 3)
        self.assertEqual(len(self.calls), 4, 'snapshot timeouts must not recursively take snapshots')
        self.assertEqual(self.calls[-1][0], ['podman', 'top', 'fpe-exit', 'pid,ppid,state,etime,comm'])
        self.assertEqual([kwargs['timeout'] for _, kwargs in self.calls], [40, 3, 3, 3])
        for path in self.root.iterdir(): self.assertNotIn('secret-', path.read_text())

    def test_join_and_interactive_exec_never_retry_or_expose_arguments(self):
        for args in [
            ['podman', 'exec', 'fpe-cli', 'fluxpeer', 'join', 'secret-invite'],
            ['podman', 'exec', '-i', 'fpe-exit', 'sh', '-c', 'cat > secret-path'],
        ]:
            with self.subTest(args=args):
                before = len(self.calls)
                with self.assertRaises(RuntimeError) as error: self.ns['need'](args, data='secret-stdin')
                self.assertNotIn('secret-', str(error.exception))
                self.assertEqual(len(self.calls) - before, 4)
        for path in self.root.iterdir(): self.assertNotIn('secret-', path.read_text())

    def test_nonexec_timeouts_and_api_opt_out_do_not_duplicate_diagnostics(self):
        rc, _, _ = self.ns['run'](['podman', 'ps'])
        self.assertEqual(rc, 124)
        rc, _, _ = self.ns['run'](['podman', 'exec', 'fpe-ctl', 'curl'], diagnose=False)
        self.assertEqual(rc, 124)
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == '__main__': unittest.main()
