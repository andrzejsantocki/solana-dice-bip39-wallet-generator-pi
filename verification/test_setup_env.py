import re
import unittest
from pathlib import Path


class SetupEnvTests(unittest.TestCase):
    def test_setup_env_never_upgrades_pip_online(self):
        text = Path('setup_env.sh').read_text(encoding='utf-8').lower()
        self.assertNotIn('install --upgrade pip', text)
        self.assertIn('--no-index', text)
        self.assertIn('--require-hashes', text)
        self.assertIn('missing pkgs folder. refusing online install.', text)

    def test_setup_env_requires_python_311_aarch64_for_bundled_wheels(self):
        text = Path('setup_env.sh').read_text(encoding='utf-8').lower()
        self.assertIn('requires cpython 3.11', text)
        self.assertIn("sys.version_info[:2] == (3, 11)", text)
        self.assertIn("struct.calcsize('p') * 8 == 64", text)
        self.assertIn('aarch64', text)

    def test_setup_env_uses_explicit_venv_interpreter_for_pip(self):
        text = Path('setup_env.sh').read_text(encoding='utf-8')
        self.assertIn('"$VENV/bin/python" -m pip install', text)
        # No PATH-dependent bare pip/python install anywhere.
        self.assertIsNone(re.search(r'^\s*pip\s+install', text, re.M))
        self.assertIsNone(re.search(r'^\s*python\s+-m\s+pip', text, re.M))
        # No activation-based install step.
        self.assertNotIn('activate', text)


if __name__ == '__main__':
    unittest.main()
