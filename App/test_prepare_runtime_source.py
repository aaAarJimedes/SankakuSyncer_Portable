# -*- coding: utf-8 -*-
"""Offline tests for the verified full-runtime source builder."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from tools.prepare_runtime_source import (
    DEFAULT_LOCK,
    RuntimeSourceError,
    SENTINEL_BYTES,
    SENTINEL_NAME,
    _canonical_distribution,
    _read_lock,
    build_runtime_source,
)
from tools.portable_self_check import read_locked_requirements


class RuntimeSourceBuilderTests(unittest.TestCase):
    def test_checked_in_artifact_lock_matches_dependency_lock(self):
        target, artifacts = _read_lock(DEFAULT_LOCK)
        dependency_lock = read_locked_requirements(
            DEFAULT_LOCK.parent / "requirements.lock.txt"
        )
        wheel_versions = {
            _canonical_distribution(str(record["distribution"])): str(record["version"])
            for record in artifacts
            if record["kind"] == "wheel"
        }

        self.assertEqual(target["python"], "3.13.15")
        self.assertEqual(target["transport"], "winhttp-schannel")
        self.assertEqual(target["pyside6"], dependency_lock["pyside6"][1])
        self.assertEqual(
            wheel_versions,
            {name: version for name, (_display, version) in dependency_lock.items()},
        )

    def _archive(self, path: Path, files: dict[str, bytes]) -> dict[str, object]:
        with zipfile.ZipFile(path, "w") as archive:
            for name, value in files.items():
                archive.writestr(name, value)
        payload = path.read_bytes()
        return {
            "filename": path.name,
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def _fixture(self, root: Path, *, unsafe_wheel: bool = False):
        wheelhouse = root / "wheelhouse"
        wheelhouse.mkdir()
        python = self._archive(
            wheelhouse / "python.zip",
            {
                "python.exe": b"exe",
                "pythonw.exe": b"exew",
                "python313.dll": b"dll",
                "python313.zip": b"stdlib",
                "python313._pth": b"# import site\n",
                "LICENSE.txt": b"PSF license",
            },
        )
        wheel_members = {
            "demo/__init__.py": b"__version__ = '1.0'\n",
            "demo-1.0.dist-info/METADATA": b"Name: demo\nVersion: 1.0\n\n",
        }
        if unsafe_wheel:
            wheel_members["../escape.txt"] = b"escape"
        wheel = self._archive(wheelhouse / "demo-1.0-py3-none-any.whl", wheel_members)
        lock = root / "lock.json"
        lock.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "target": {
                        "os": "windows",
                        "architecture": "x86_64",
                        "python": "3.13.15",
                        "python_abi": "cp313",
                        "pyside6": "6.11.2",
                        "transport": "winhttp-schannel",
                    },
                    "artifacts": [
                        {
                            "kind": "python_embed",
                            "distribution": "CPython",
                            "version": "3.13.15",
                            "url": "https://www.python.org/example",
                            **python,
                        },
                        {
                            "kind": "wheel",
                            "distribution": "demo",
                            "version": "1.0",
                            "url": "https://pypi.org/example",
                            **wheel,
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        return lock, wheelhouse

    def test_build_verifies_and_extracts_embed_and_wheel(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, wheelhouse = self._fixture(root)
            destination = root / "verified_runtime_source_build"

            report = build_runtime_source(lock, wheelhouse, destination, clean=False)

            self.assertEqual(report["target"]["python"], "3.13.15")
            self.assertEqual(
                (destination / "Lib" / "site-packages" / "demo" / "__init__.py").read_text(),
                "__version__ = '1.0'\n",
            )
            self.assertIn(
                "Lib\\site-packages",
                (destination / "python313._pth").read_text("utf-8"),
            )
            self.assertEqual((destination / SENTINEL_NAME).read_bytes(), SENTINEL_BYTES)

    def test_hash_mismatch_is_rejected_before_existing_build_is_cleaned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, wheelhouse = self._fixture(root)
            payload = json.loads(lock.read_text("utf-8"))
            payload["artifacts"][0]["sha256"] = "0" * 64
            lock.write_text(json.dumps(payload), encoding="utf-8")
            destination = root / "verified_runtime_source_build"
            destination.mkdir()
            (destination / SENTINEL_NAME).write_bytes(SENTINEL_BYTES)
            preserved = destination / "preserved.txt"
            preserved.write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeSourceError, "hash mismatch"):
                build_runtime_source(lock, wheelhouse, destination, clean=True)

            self.assertEqual(preserved.read_text("utf-8"), "keep")

    def test_clean_requires_exact_builder_sentinel(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, wheelhouse = self._fixture(root)
            destination = root / "verified_runtime_source_build"
            destination.mkdir()
            (destination / "user.txt").write_text("owned", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeSourceError, "exact builder sentinel"):
                build_runtime_source(lock, wheelhouse, destination, clean=True)

            self.assertTrue((destination / "user.txt").is_file())

    def test_archive_traversal_is_rejected_before_destination_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock, wheelhouse = self._fixture(root, unsafe_wheel=True)
            destination = root / "verified_runtime_source_build"

            with self.assertRaisesRegex(RuntimeSourceError, "escapes destination"):
                build_runtime_source(lock, wheelhouse, destination, clean=False)

            self.assertFalse(destination.exists())
            self.assertFalse((root / "escape.txt").exists())


if __name__ == "__main__":
    unittest.main()
