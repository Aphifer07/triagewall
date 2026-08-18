from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def v04_release_state_is_valid(changelog: str, evidence_exists: bool) -> bool:
    released = bool(
        re.search(
            r"^## \[v0\.4\]\(https://github\.com/aaronphifer/triagewall/"
            r"releases/tag/v0\.4\) - \d{4}-\d{2}-\d{2}$",
            changelog,
            re.MULTILINE,
        )
    )
    return not released or evidence_exists


class ReleaseDocumentationTests(unittest.TestCase):
    def test_demo_pulls_default_model_before_starting_stack(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        demo = readme.split("## Five-minute demo", 1)[1].split("\n## ", 1)[0]
        model_pull = (
            "ollama pull "
            "hf.co/gabriellarson/Foundation-Sec-8B-Instruct-GGUF:Q5_K_M"
        )

        self.assertIn(model_pull, demo)
        self.assertLess(demo.index(model_pull), demo.index("docker compose up -d"))

    def test_v04_changelog_release_state_matches_evidence(self):
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        evidence_exists = (ROOT / "docs" / "release-evidence-v0.4.md").is_file()

        self.assertTrue(
            v04_release_state_is_valid(changelog, evidence_exists),
            "v0.4 must remain Unreleased until its production evidence is committed",
        )

    def test_v04_release_document_state_matrix(self):
        released = (
            "## [v0.4](https://github.com/aaronphifer/triagewall/"
            "releases/tag/v0.4) - 2026-08-18"
        )
        unreleased = "## Unreleased"

        cases = (
            (unreleased, False, True),
            (unreleased, True, True),
            (released, False, False),
            (released, True, True),
        )
        for changelog, evidence_exists, expected in cases:
            with self.subTest(
                released=changelog == released,
                evidence_exists=evidence_exists,
            ):
                self.assertEqual(
                    v04_release_state_is_valid(changelog, evidence_exists),
                    expected,
                )


if __name__ == "__main__":
    unittest.main()
