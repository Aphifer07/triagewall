from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseDocumentationTests(unittest.TestCase):
    def test_v04_changelog_release_state_matches_evidence(self):
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        released = bool(
            re.search(
                r"^## \[v0\.4\]\(https://github\.com/aaronphifer/triagewall/"
                r"releases/tag/v0\.4\) - \d{4}-\d{2}-\d{2}$",
                changelog,
                re.MULTILINE,
            )
        )
        evidence_exists = (ROOT / "docs" / "release-evidence-v0.4.md").is_file()

        self.assertEqual(
            released,
            evidence_exists,
            "v0.4 must remain Unreleased until its production evidence is committed",
        )


if __name__ == "__main__":
    unittest.main()
