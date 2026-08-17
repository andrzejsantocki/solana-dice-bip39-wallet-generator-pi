import unittest
from pathlib import Path


class ReadmeAccuracyTests(unittest.TestCase):
    def test_readme_matches_dependency_runtime_model(self):
        text = Path('README.md').read_text(encoding='utf-8').lower()
        self.assertIn('wallet generation performs zero package installation', text)
        self.assertIn('setup_env.sh', text)
        self.assertNotIn('--force-reinstall', text)
        self.assertNotIn('startup performs a pip reinstall', text)
        self.assertIn('bip39 passphrase compatibility', text)
        self.assertIn('by default, this tool uses no bip39 passphrase', text)
        self.assertIn('--bip39-passphrase', text)
        self.assertIn('phantom/solflare recovery flows that ask for only the 12/24 words', text)

    def test_readme_test_claims_match_repository_reality(self):
        text = Path('README.md').read_text(encoding='utf-8').lower()
        self.assertIn('python -m unittest discover', text)
        self.assertIn('ci runs these tests on every push/pr', text)
        for fname in ('verification/test_published_vectors.py', 'verification/test_operational_safety.py',
                      'verification/test_setup_env.py', 'verification/test_ci_pinning.py', 'verification/test_readme_accuracy.py'):
            self.assertTrue(Path(fname).exists(), f'{fname} missing but README claims a test suite')
        self.assertTrue(Path('.github/workflows/tests.yml').exists(), 'CI workflow missing but README claims CI')

    def test_readme_documents_same_die_ceremony_requirement(self):
        text = Path('README.md').read_text(encoding='utf-8').lower()
        self.assertIn('one physical d6', text)
        self.assertIn('do not assign', text)

    def test_readme_has_no_misleading_numeric_score(self):
        text = Path('README.md').read_text(encoding='utf-8')
        self.assertNotIn('/100', text)


if __name__ == '__main__':
    unittest.main()
