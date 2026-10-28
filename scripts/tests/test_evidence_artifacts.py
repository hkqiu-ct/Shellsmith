import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.evidence.collect_artifacts import file_entry, git_commit, sha256_file, zip_summary


class EvidenceArtifactTests(unittest.TestCase):
    def test_sha256_and_zip_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "sample.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", b"dex\n035\0")
                archive.writestr("lib/arm64-v8a/libdemo.so", b"\x7fELF")
                archive.writestr("assets/protector/aenc/x", b"x")
                archive.writestr("AndroidManifest.xml", b"manifest")
            digest = sha256_file(apk)
            self.assertEqual(len(digest), 64)
            summary = zip_summary(apk)
            self.assertEqual(summary["dex_entries"], ["classes.dex"])
            self.assertEqual(summary["native_libs"], {"arm64-v8a": 1})
            self.assertEqual(summary["asset_entries"], 1)
            self.assertTrue(summary["has_manifest"])

    def test_file_entry_has_stable_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.bin"
            path.write_bytes(b"evidence")
            entry = file_entry(path, "baseline", None)
            self.assertEqual(entry["sha256"], sha256_file(path))
            self.assertEqual(entry["size_bytes"], 8)
            self.assertEqual(entry["label"], "baseline")
            self.assertEqual(entry["suffix"], ".bin")

    def test_git_commit_returns_none_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertIsNone(git_commit(Path(directory)))

    def test_manifest_json_is_serializable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.apk"
            path.write_bytes(b"x")
            payload = {"schema_version": 1, "files": [file_entry(path, "x", None)]}
            json.dumps(payload)
            self.assertEqual(payload["files"][0]["name"], "a.apk")


if __name__ == "__main__":
    unittest.main()
