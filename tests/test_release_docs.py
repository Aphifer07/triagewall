from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


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
