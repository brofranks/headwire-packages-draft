"""Check publication gates without accessing signing credentials or GitHub."""

import unittest
from pathlib import Path

import yaml


class PublicationTests(unittest.TestCase):
    def test_package_publication_is_manual(self):
        path = Path(__file__).resolve().parents[1] / ".github/workflows/publish.yml"
        workflow = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow["on"]), {"pull_request", "push", "workflow_dispatch"})
        self.assertEqual(workflow["on"]["push"]["branches"], ["main"])
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertNotIn("concurrency", workflow)
        check = workflow["jobs"]["check"]
        self.assertNotIn("concurrency", check)
        self.assertNotIn("if", check)
        self.assertNotIn("environment", check)
        self.assertNotIn("secrets.", str(check))
        publisher = workflow["jobs"]["publish"]
        self.assertEqual(publisher["if"], "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'")
        self.assertEqual(publisher["needs"], "check")
        self.assertEqual(publisher["environment"], "repository")
        self.assertEqual(
            publisher["permissions"],
            {"contents": "read", "pages": "write", "id-token": "write", "attestations": "read"},
        )
        self.assertEqual(
            publisher["concurrency"],
            {"group": "package-repositories", "cancel-in-progress": "false"},
        )
