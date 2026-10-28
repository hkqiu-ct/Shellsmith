import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class EvidenceToolTests(unittest.TestCase):
    def run_python(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, *args],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def test_recovery_benchmark_records_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bench.json"
            result = self.run_python(
                "scripts/evidence/recovery_benchmark.py",
                "--name",
                "smoke",
                "--command",
                f"{sys.executable} -c 'print(1)'",
                "--output",
                str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload["all_succeeded"])
            self.assertEqual(payload["runs"][0]["exit_code"], 0)

    def test_recovery_benchmark_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "bench.json"
            result = self.run_python(
                "scripts/evidence/recovery_benchmark.py",
                "--name",
                "dry",
                "--command",
                "true",
                "--output",
                str(output),
                "--dry-run",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload["dry_run"])
            self.assertIsNone(payload["all_succeeded"])

    def test_differential_command_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "diff.json"
            command = f"{sys.executable} tests/fixtures/evidence/run_case.py"
            result = self.run_python(
                "scripts/evidence/differential_test.py",
                "--original-cmd",
                command,
                "--protected-cmd",
                command,
                "--cases",
                "tests/fixtures/evidence/cases.json",
                "--output",
                str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["failed"], 0)
            self.assertEqual(payload["case_count"], 3)

    def test_differential_detects_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "diff.json"
            result = self.run_python(
                "scripts/evidence/differential_test.py",
                "--original-cmd",
                f"{sys.executable} -c 'print(1)'",
                "--protected-cmd",
                f"{sys.executable} -c 'print(2)'",
                "--cases",
                "tests/fixtures/evidence/cases.json",
                "--output",
                str(output),
            )
            self.assertEqual(result.returncode, 1)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["failed"], 3)

    def test_evidence_ready_baseline(self) -> None:
        result = subprocess.run(
            ["bash", "scripts/check-evidence-ready.sh", "--baseline"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("证据检查通过", result.stdout)


if __name__ == "__main__":
    unittest.main()
