import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("local_tools", Path(__file__).parents[1] / "scripts/local.py")
local = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local)


class ToolTests(unittest.TestCase):
    def test_credential_environment_is_not_inherited(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(local, "LOCAL", Path(directory)), patch.dict(
                "os.environ", {"OPENAI_API_KEY": "test-only", "AWS_SECRET_ACCESS_KEY": "test-only"}
            ):
                environment = local.environment()
                self.assertNotIn("OPENAI_API_KEY", environment)
                self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
                self.assertEqual(environment["OPENSHELL_KATA_STATE_DIR"], str(Path(directory) / "runtime"))

    def with_cli(self, body, check):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin/openshell"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\n" + body)
            binary.chmod(0o755)
            with patch.object(local, "LOCAL", root), patch.object(local, "ROOT", root), patch.object(local, "EVIDENCE", root / "evidence"):
                check(root)

    def test_failure_is_recorded_before_raising(self):
        def check(root):
            with self.assertRaisesRegex(RuntimeError, "expected failure"):
                local.cli("test", label="failure")
            result = json.loads((root / "evidence/failure.json").read_text())
            self.assertEqual(result["exit_code"], 7)
            self.assertEqual(result["stdout"], "output\n")
        self.with_cli("echo output\necho 'expected failure' >&2\nexit 7\n", check)

    def test_timeout_closes_descendant_output_pipes(self):
        def check(_root):
            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                local.cli("test", timeout=0.1, label="timeout")
            self.assertLess(time.monotonic() - started, 5)
        self.with_cli("sleep 30 &\nwait\n", check)


if __name__ == "__main__":
    unittest.main()
