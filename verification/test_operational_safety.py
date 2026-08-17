import ast
import hashlib
import io
import random
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import generate_wallet as gw


class OperationalSafetyTests(unittest.TestCase):
    def test_generator_does_zero_runtime_package_installation(self):
        tree = ast.parse(Path('generate_wallet.py').read_text(encoding='utf-8'))
        imports = {alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names}
        self.assertNotIn('subprocess', imports)
        self.assertNotIn('os', imports)
        text = Path('generate_wallet.py').read_text(encoding='utf-8').lower()
        self.assertNotIn('--force-reinstall', text)
        self.assertNotIn('pip install', text)

    def test_unused_crypto_and_ascii_dependencies_removed(self):
        text = Path('generate_wallet.py').read_text(encoding='utf-8').lower()
        req = Path('requirements-hashes.txt').read_text(encoding='utf-8').lower()
        self.assertNotIn('pyfiglet', text + req)
        self.assertNotIn('ecdsa', text + req)
        self.assertNotIn('ripemd160', text)
        self.assertNotIn('secp256k1', text)

    def test_gap_check_does_not_reprint_or_echo_correct_words(self):
        words = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
        answers = iter(['wrong'] * 5)
        with patch('generate_wallet.random.sample', return_value=[0, 1, 2, 3, 4]), patch('generate_wallet.getpass.getpass', lambda _prompt: next(answers)):
            buf = io.StringIO()
            with redirect_stdout(buf), self.assertRaises(SystemExit):
                gw.mnemonic_gap_check(words)
        out = buf.getvalue()
        self.assertIn('Mnemonic is not reprinted here', out)
        self.assertNotIn(words, out)
        self.assertNotIn('abandon abandon', out)
        self.assertNotIn('-> abandon', out)

    def test_hash_roll_count_has_safe_minimum(self):
        with self.assertRaises(SystemExit):
            gw.parse_args(['--entropy-mode', 'hash-rolls', '--roll-count', '1'])

    def test_suspect_entropy_aborts(self):
        q = gw.analyze_roll_quality([1, 2] * 20, [(1, 2)] * 20, 16)
        with self.assertRaises(SystemExit):
            gw.abort_if_not_good(q)

    def test_bip39_passphrase_is_explicit_opt_in(self):
        args = gw.parse_args([])
        self.assertFalse(args.bip39_passphrase)
        args = gw.parse_args(['--bip39-passphrase'])
        self.assertTrue(args.bip39_passphrase)

    def test_die_roll_input_uses_hidden_getpass(self):
        text = Path('generate_wallet.py').read_text(encoding='utf-8')
        self.assertIn('def hidden_die_roll', text)
        self.assertIn('getpass.getpass(prompt)', text)
        self.assertNotIn('raw = input(', text)

    def test_fair_von_neumann_sessions_mostly_pass_gate(self):
        random.seed(1234)
        passes = 0
        trials = 200
        for _ in range(trials):
            rolls = []
            pairs = []
            bits = 0
            while bits < 256:
                a = random.randint(1, 6); b = random.randint(1, 6)
                rolls.extend([a, b]); pairs.append((a, b))
                if a != b: bits += 1
            q = gw.analyze_roll_quality(rolls, pairs, 256)
            if not q['warnings']:
                passes += 1
        self.assertGreaterEqual(passes / trials, 0.90)

    def test_import_location_verification_exists(self):
        text = Path('generate_wallet.py').read_text(encoding='utf-8')
        self.assertIn('def verify_import_locations', text)
        self.assertIn('Path(sys.prefix).resolve()', text)

    def test_pkgs_allowlist_rejects_extra_wheels(self):
        data = b'fake-wheel-content'
        with tempfile.TemporaryDirectory() as d:
            names = ('mnemonic-0.21-py3-none-any.whl',
                     'pynacl-1.6.2-py3-none-any.whl',
                     'cffi-2.1.1-py3-none-any.whl',
                     'pycparser-3.0-py3-none-any.whl',
                     'evil-9.9-py3-none-any.whl')
            for fname in names:
                Path(d, fname).write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            expected = {'mnemonic': ('0.21', digest),
                        'pynacl': ('1.6.2', digest),
                        'cffi': ('2.1.1', digest),
                        'pycparser': ('3.0', digest)}
            with patch('generate_wallet.PKGS_DIR', Path(d)):
                with self.assertRaises(SystemExit):
                    gw._verify_local_wheel_hashes(expected)

    def test_pkgs_allowlist_accepts_exact_wheel_set(self):
        data = b'fake-wheel-content'
        with tempfile.TemporaryDirectory() as d:
            names = ('mnemonic-0.21-py3-none-any.whl',
                     'pynacl-1.6.2-py3-none-any.whl',
                     'cffi-2.1.1-py3-none-any.whl',
                     'pycparser-3.0-py3-none-any.whl')
            for fname in names:
                Path(d, fname).write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            expected = {'mnemonic': ('0.21', digest),
                        'pynacl': ('1.6.2', digest),
                        'cffi': ('2.1.1', digest),
                        'pycparser': ('3.0', digest)}
            with patch('generate_wallet.PKGS_DIR', Path(d)):
                gw._verify_local_wheel_hashes(expected)

    def test_wheel_match_requires_exact_name_version_separator(self):
        data = b'fake-wheel-content'
        with tempfile.TemporaryDirectory() as d:
            Path(d, 'foo-10-py3-none-any.whl').write_bytes(data)
            expected = {'foo': ('1', hashlib.sha256(data).hexdigest())}
            with patch('generate_wallet.PKGS_DIR', Path(d)):
                with self.assertRaises(SystemExit):
                    gw._verify_local_wheel_hashes(expected)

    def test_misleading_numeric_score_removed(self):
        q = gw.analyze_roll_quality([1, 2, 3, 4, 5, 6] * 20)
        self.assertNotIn('score', q)
        text = Path('generate_wallet.py').read_text(encoding='utf-8')
        self.assertNotIn('Score:', text)
        self.assertNotIn('/100', text)

    def test_private_derivation_requires_explicit_confirmation(self):
        bits = [0] * 256
        with patch('generate_wallet.collect_entropy_bits', return_value=bits), \
             patch('generate_wallet.getpass.getpass', return_value='nope'):
            buf = io.StringIO()
            with redirect_stdout(buf), self.assertRaises(SystemExit) as cm:
                gw.main(['--show-private-derivations', '--no-gap-check', '--color', 'never'])
        self.assertIn('not confirmed', str(cm.exception))

    def test_private_derivation_prints_only_after_confirmation(self):
        bits = [0] * 256
        with patch('generate_wallet.collect_entropy_bits', return_value=bits), \
             patch('generate_wallet.getpass.getpass', return_value='SHOW PRIVATE KEYS'):
            buf = io.StringIO()
            with redirect_stdout(buf):
                gw.main(['--show-private-derivations', '--no-gap-check', '--color', 'never'])
        self.assertIn('Seed hex:', buf.getvalue())

    def test_biased_iid_die_passes_von_neumann_gate_but_fails_hash_gate(self):
        # Face 1 twice as likely as any other face: still IID, so the
        # </> extractor output is unbiased; hash-rolls must reject it.
        rng = random.Random(42)
        rolls, pairs, bits = [], [], 0
        while bits < 256:
            a = rng.choices([1, 2, 3, 4, 5, 6], weights=[2, 1, 1, 1, 1, 1])[0]
            b = rng.choices([1, 2, 3, 4, 5, 6], weights=[2, 1, 1, 1, 1, 1])[0]
            rolls.extend([a, b]); pairs.append((a, b))
            if a != b: bits += 1
        q_vn = gw.analyze_roll_quality(rolls, pairs, 256, mode='von-neumann')
        self.assertEqual(q_vn['warnings'], [])
        q_hash = gw.analyze_roll_quality(rolls, pairs, 256, mode='hash-rolls')
        self.assertTrue(q_hash['warnings'])

    def test_von_neumann_collection_uses_structural_gate_mode(self):
        text = Path('generate_wallet.py').read_text(encoding='utf-8')
        self.assertIn("mode='von-neumann'", text)


if __name__ == '__main__':
    unittest.main()
