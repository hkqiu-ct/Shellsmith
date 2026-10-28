import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class EvidenceDeviceToolTests(unittest.TestCase):
    def run_python(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def test_device_acceptance_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "device.json"
            result = self.run_python(
                "scripts/evidence/device_acceptance.py",
                "--serial",
                "serial",
                "--package",
                "com.example.app",
                "--output",
                str(output),
                "--dry-run",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload["dry_run"])
            self.assertEqual(payload["package"], "com.example.app")

    def test_byos_probe_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "byos.json"
            result = self.run_python(
                "scripts/evidence/byos_probe.py",
                "--base-url",
                "https://keys.example.com",
                "--output",
                str(output),
                "--dry-run",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload["dry_run"])
            self.assertGreaterEqual(len(payload["cases"]), 5)

    def test_aab_local_verify_requires_bundle(self) -> None:
        result = subprocess.run(
            ["bash", "scripts/evidence/aab_local_verify.sh"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("需要 --bundle", result.stderr)


if __name__ == "__main__":
    unittest.main()
