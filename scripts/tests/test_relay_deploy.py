# SPDX-License-Identifier: BSD-3-Clause
"""Exercise the deployment driver's arguments with a fake Podman executable."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RelayVolume(unittest.TestCase):
    def test_replacement_reuses_default_or_explicit_identity_volume(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            podman = path / 'podman'
            podman.write_text('#!' + sys.executable + '\n' +
                              'import json, os, sys\n' +
                              'with open(os.environ["MOCK_LOG"], "a") as out: out.write(json.dumps(sys.argv[1:]) + "\\n")\n' +
                              'if sys.argv[1] == "info": print("crun")\n')
            podman.chmod(0o700)
            log = path / 'calls.jsonl'
            env = dict(os.environ, PATH=str(path) + os.pathsep + os.environ['PATH'],
                       MOCK_LOG=str(log), FLUXPEER_PODMAN_DIR=str(path / 'state'))
            for volume, extra in [('fluxpeer-relay-data', []), ('custom-relay-data', ['--data', 'custom-relay-data'])]:
                log.write_text('')
                for _ in range(2):
                    subprocess.run(['bash', str(ROOT / 'deploy/fluxpeer-podman'), 'up', 'relay', '--port', '13478', *extra],
                                   env=env, check=True, capture_output=True, text=True)
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                runs = [call for call in calls if call[0] == 'run']
                self.assertEqual(len(runs), 2)
                for run in runs:
                    self.assertEqual(run[run.index('-v') + 1], volume + ':/data')
                    self.assertIn('FLUXPEER_DATA_DIR=/data', run)
                    self.assertEqual(run[-1], 'relay')
                    self.assertIn('13478:3478/tcp', run)
                self.assertEqual([c for c in calls if c[0] == 'rm'], [['rm', '-f', 'fluxpeer-relay']] * 2)
                self.assertFalse(any(c[0] == 'volume' for c in calls))


if __name__ == '__main__': unittest.main()
