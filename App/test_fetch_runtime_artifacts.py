# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError

from tools import fetch_runtime_artifacts as fetcher


class _Response(io.BytesIO):
    def __init__(self, payload: bytes, url: str, headers: dict[str, str] | None = None):
        super().__init__(payload)
        self._url = url
        self.headers = headers or {}

    def geturl(self) -> str:
        return self._url


class FetchRuntimeArtifactsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.payload = b"locked artifact bytes"
        self.url = "https://files.pythonhosted.org/packages/example.whl"
        self.lock = self.root / "lock.json"
        self.lock.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "artifacts": [
                        {
                            "filename": "example.whl",
                            "url": self.url,
                            "bytes": len(self.payload),
                            "sha256": hashlib.sha256(self.payload).hexdigest(),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.wheelhouse = self.root / "wheelhouse"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_downloads_and_authenticates_locked_payload(self) -> None:
        results = fetcher.fetch_artifacts(
            self.lock,
            self.wheelhouse,
            opener=lambda url: _Response(
                self.payload,
                url,
                {"Content-Length": str(len(self.payload))},
            ),
        )
        self.assertEqual(results, [("example.whl", "downloaded")])
        self.assertEqual((self.wheelhouse / "example.whl").read_bytes(), self.payload)
        self.assertFalse((self.wheelhouse / ".example.whl.part").exists())

    def test_matching_existing_file_is_reused_without_network(self) -> None:
        self.wheelhouse.mkdir()
        (self.wheelhouse / "example.whl").write_bytes(self.payload)
        results = fetcher.fetch_artifacts(
            self.lock,
            self.wheelhouse,
            opener=lambda _url: self.fail("network should not be used"),
        )
        self.assertEqual(results, [("example.whl", "verified")])

    def test_invalid_existing_file_is_not_overwritten(self) -> None:
        self.wheelhouse.mkdir()
        target = self.wheelhouse / "example.whl"
        target.write_bytes(b"user file")
        with self.assertRaises(fetcher.ArtifactFetchError):
            fetcher.fetch_artifacts(self.lock, self.wheelhouse, opener=lambda _url: None)
        self.assertEqual(target.read_bytes(), b"user file")

    def test_wrong_payload_is_removed_without_publishing(self) -> None:
        with self.assertRaises(fetcher.ArtifactFetchError):
            fetcher.fetch_artifacts(
                self.lock,
                self.wheelhouse,
                opener=lambda url: _Response(b"wrong", url),
            )
        self.assertFalse((self.wheelhouse / "example.whl").exists())
        self.assertFalse((self.wheelhouse / ".example.whl.part").exists())

    def test_redirect_outside_locked_hosts_is_rejected(self) -> None:
        def redirect(_url: str):
            raise HTTPError(
                self.url,
                302,
                "redirect",
                {"Location": "https://evil.example/payload"},
                None,
            )

        with self.assertRaises(fetcher.ArtifactFetchError):
            fetcher.fetch_artifacts(self.lock, self.wheelhouse, opener=redirect)

    def test_encoded_or_oversized_response_is_rejected(self) -> None:
        for payload, headers in (
            (self.payload, {"Content-Encoding": "gzip"}),
            (self.payload + b"x", {}),
        ):
            with self.subTest(headers=headers, size=len(payload)):
                with tempfile.TemporaryDirectory(dir=self.root) as directory:
                    with self.assertRaises(fetcher.ArtifactFetchError):
                        fetcher.fetch_artifacts(
                            self.lock,
                            Path(directory) / "wheelhouse",
                            opener=lambda url, data=payload, h=headers: _Response(data, url, h),
                        )

    def test_unsafe_lock_url_and_filename_fail_before_network(self) -> None:
        original = json.loads(self.lock.read_text("utf-8"))
        for filename, url in (
            ("../escape.whl", self.url),
            ("example.whl", "http://files.pythonhosted.org/example.whl"),
            ("example.whl", "https://user:pass@files.pythonhosted.org/example.whl"),
        ):
            with self.subTest(filename=filename, url=url):
                payload = json.loads(json.dumps(original))
                payload["artifacts"][0]["filename"] = filename
                payload["artifacts"][0]["url"] = url
                self.lock.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaises(fetcher.ArtifactFetchError):
                    fetcher.fetch_artifacts(
                        self.lock,
                        self.wheelhouse,
                        opener=lambda _url: self.fail("network should not be used"),
                    )
        self.lock.write_text(json.dumps(original), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
