from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]

FOUNDATION_DOC = ROOT / "docs" / "operator-configuration-foundation.md"

STALE_CURRENT_STATE_HEADING = re.compile(r"^## Current state\s*$", re.MULTILINE)

HISTORICAL_HEADING = re.compile(
    r"^## .*(pre-v0\.4|pre-implementation|historical).*$",
    re.MULTILINE | re.IGNORECASE,
)


def section_after(document: str, heading: str) -> str:
    """Return the body under ``heading`` up to the next level-two heading."""
    return document.split(heading, 1)[1].split("\n## ", 1)[0]


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


PERSISTED_VERDICT_HEADING = "### Source-specific persisted verdicts"

PERSISTED_VERDICT_ROW = re.compile(
    r"^\|\s*(Suricata|Wazuh)\s*\|\s*([\d,]+)\s*\|",
    re.MULTILINE | re.IGNORECASE,
)


def persisted_verdict_section(document: str) -> str:
    """Return the source-specific persisted-verdict section, or "" if absent."""
    if PERSISTED_VERDICT_HEADING not in document:
        return ""
    tail = document.split(PERSISTED_VERDICT_HEADING, 1)[1]
    return tail.split("\n## ", 1)[0].split("\n### ", 1)[0]


def persisted_verdict_counts(section: str) -> dict:
    """Map lowercase source name to its persisted-verdict count."""
    return {
        match.group(1).lower(): int(match.group(2).replace(",", ""))
        for match in PERSISTED_VERDICT_ROW.finditer(section)
    }


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


    def test_v04_evidence_proves_persisted_verdicts_for_both_sources(self):
        """Checkpoint movement alone is not proof: skipped, non-alert, invalid,
        and duplicate records advance a checkpoint without persisting a verdict,
        and /api/health is a global aggregate that one source can satisfy."""
        document = (
            ROOT / "docs" / "release-evidence-v0.4.md"
        ).read_text(encoding="utf-8")
        section = persisted_verdict_section(document)

        self.assertTrue(
            section,
            "v0.4 evidence must contain a "
            f"'{PERSISTED_VERDICT_HEADING}' section",
        )

        counts = persisted_verdict_counts(section)
        for source in ("suricata", "wazuh"):
            with self.subTest(source=source):
                self.assertIn(
                    source,
                    counts,
                    f"{source} needs a persisted-verdict row",
                )
                self.assertGreater(
                    counts[source],
                    0,
                    f"{source} must show a positive persisted-verdict count",
                )

        self.assertRegex(
            section,
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
            "the section must identify a bounded query window",
        )
        self.assertIn("query window", section.lower())
        self.assertIn("persisted verdict", section.lower())
        self.assertIn(
            "checkpoint",
            section.lower(),
            "the section must distinguish persisted verdicts from "
            "checkpoint movement",
        )


    def test_implemented_foundation_doc_labels_its_historical_baseline(self):
        """Once the foundation is marked implemented, the section describing the
        old static, startup-only system must be labelled as history rather than
        as the current runtime."""
        document = FOUNDATION_DOC.read_text(encoding="utf-8")
        self.assertIn(
            "implemented in v0.4",
            document,
            "this invariant applies to the implemented foundation document",
        )

        self.assertNotRegex(
            document,
            STALE_CURRENT_STATE_HEADING,
            "the historical static system must not be headed 'Current state'",
        )

        heading = HISTORICAL_HEADING.search(document)
        self.assertIsNotNone(
            heading,
            "the document needs an explicit pre-v0.4 baseline heading",
        )

        section = section_after(document, heading.group(0))
        self.assertRegex(
            section,
            r"(?is)motivat",
            "the baseline section must say it motivated the design",
        )
        self.assertRegex(
            section,
            r"(?is)does not describe.{0,160}v0\.4",
            "the baseline section must disclaim describing the v0.4 runtime",
        )
        self.assertNotRegex(
            section,
            r"(?i)the current implementation is",
            "the baseline section must not present itself as current",
        )


if __name__ == "__main__":
    unittest.main()
