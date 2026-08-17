import re
import unittest
from pathlib import Path


class CiPinningTests(unittest.TestCase):
    def test_github_actions_use_full_commit_shas(self):
        text = Path('.github/workflows/tests.yml').read_text(encoding='utf-8')
        uses = re.findall(r'uses:\s*[^@]+@([^\s#]+)', text)
        self.assertTrue(uses)
        for ref in uses:
            self.assertRegex(ref, r'^[0-9a-f]{40}$')


if __name__ == '__main__':
    unittest.main()
