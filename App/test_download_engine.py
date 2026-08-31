# -*- coding: utf-8 -*-
"""Offline media-download tests using only in-memory fakes and temp dirs."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import json
import os
import stat
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from bound_file_reader import BoundFileUnreadable, BoundRootSession, open_bound_root
import download_engine
import request_gate
from download_engine import (
    DownloadError,
    DownloadResult,
    LocalIntegrityError,
    LocalMetadataError,
    MediaAccessDeniedError,
    MediaDownloader,
    verify_bound_local_download,
    verify_local_download,
)
from sankaku_api import (
    CancelledError,
    RateLimitError,
    SankakuPost,
)


JPEG = b"\xff\xd8\xffabc"
JPEG_ALT = b"\xff\xd8\xffxyz"
JPEG_FIVE = b"\xff\xd8\xffok"
JPEG_COMPLETE = base64.b64decode(
    b"/9j/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
    b"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/xAAmAAEAAAAAAAAAAAAAAAAA"
    b"AAAAEAEAAAAAAAAAAAAAAAAAAAAA/8AACwgAAQABAQERAP/aAAgBAQAAPwA//9k="
)
JPEG_COMPLETE_ALT = base64.b64decode(
    b"/9j/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
    b"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/xAAmAAEAAAAAAAAAAAAAAAAA"
    b"AAAAEAEAAAAAAAAAAAAAAAAAAAAA/8IACwgAAQABAQERAP/aAAgBAQAAAAB//9oA"
    b"CAEBAAE/AH//2Q=="
)
PNG_COMPLETE = base64.b64decode(
    b"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQAAAAA3bvkkAAAACklEQVR42mNg"
    b"AAAAAgAB5Sfe/AAAAABJRU5ErkJggg=="
)
GIF_COMPLETE = base64.b64decode(
    b"R0lGODdhAQABAIAAAAAAAP///ywAAAAAAQABAAACAkQBADs="
)
WEBP_COMPLETE = base64.b64decode(
    b"UklGRh4AAABXRUJQVlA4TBEAAAAvAAAAEAdQkUZ0pn+BiOh/AAA="
)
PNG = b"\x89PNG\r\n\x1a\nrest"
GIF = b"GIF89arest"
WEBP = b"RIFF\x04\x00\x00\x00WEBP"
AVIF = b"\x00\x00\x00\x18ftypavif\x00\x00\x00\x00avif"
BMP = b"BM\x1a\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00"
TIFF = b"II*\x00rest"
MP4 = b"\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isom"
MOV = b"\x00\x00\x00\x18ftypqt  \x00\x00\x00\x00qt  "
M4A = b"\x00\x00\x00\x18ftypM4A \x00\x00\x00\x00M4A "
WEBM = b"\x1a\x45\xdf\xa3\x87\x42\x82\x84webm"
MKV = b"\x1a\x45\xdf\xa3\x8b\x42\x82\x88matroska"
MPEG = b"\x00\x00\x01\xbarest"
AVI = b"RIFF\x04\x00\x00\x00AVI "
FLV = b"FLV\x01\x05\x00\x00\x00\x09"
ASF = bytes.fromhex("3026b2758e66cf11a6d900aa0062ce6c") + b"rest"
MP3 = b"ID3\x04\x00\x00\x00\x00\x00\x00\xff\xfb\x90\x64"
OGG = b"OggS\x00" + b"\x00" * 24 + b"\x01vorbis"
OPUS = b"OggS\x00" + b"\x00" * 24 + b"OpusHead"
FLAC = b"fLaCrest"
WAV = b"RIFF\x04\x00\x00\x00WAVE"
HTTP_DATE = "Wed, 21 Oct 2015 07:28:00 GMT"


class ImmediateGate:
    """No-wait stand-in; individual tests still verify gate use explicitly."""

    @contextmanager
    def slot(self, _stop_event: threading.Event, *, min_interval: float = 0.0):
        del min_interval
        yield

    def defer(self, _seconds: float) -> None:
        return None


class ObservedStopEvent:
    """Event proxy that exposes when cancellable lock polling has begun."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self.wait_entered = threading.Event()

    def is_set(self) -> bool:
        return self._event.is_set()

    def set(self) -> None:
        self._event.set()

    def wait(self, timeout: float | None = None) -> bool:
        self.wait_entered.set()
        return self._event.wait(timeout)


class FakeMediaResponse:
    """Streaming response with optional per-chunk hooks."""

    def __init__(
        self,
        status_code: int,
        *,
        headers: dict[str, str] | None = None,
        chunks: list[bytes] | None = None,
        before_chunk=None,
    ) -> None:
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.chunks = list(chunks or [])
        self.before_chunk = before_chunk
        self.closed = False

    def iter_content(self, _chunk_size: int):
        for index, chunk in enumerate(self.chunks):
            if self.before_chunk:
                self.before_chunk(index)
            yield chunk

    def close(self) -> None:
        self.closed = True


class FakeMediaSession:
    """A media session that has no path to ``requests`` or the network."""

    def __init__(self, responses: list[FakeMediaResponse]) -> None:
        self.responses = list(responses)
        self.gets: list[dict[str, object]] = []
        self.headers: dict[str, str] = {}
        self.trust_env = True
        self.closed = False

    def get(self, url: str, **kwargs) -> FakeMediaResponse:
        self.gets.append({"url": url, "kwargs": kwargs})
        if not self.responses:
            raise AssertionError("fake media session exhausted; network is forbidden")
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True


class FakeAPI:
    def __init__(self, post: SankakuPost) -> None:
        self.post = post
        self.post_ids: list[str] = []
        self.proxy = ""
        # Deliberately present secrets prove that persistence does not serialize
        # arbitrary API object state.
        self.access_token = "API_ACCESS_TOKEN_SECRET"
        self.username = "api-user-secret"
        self.password = "api-password-secret"

    def get_post(self, post_id: str) -> SankakuPost:
        self.post_ids.append(post_id)
        return self.post


def _post(
    post_id: str = "Post_1",
    *,
    file_url: str = "https://cs.sankakucomplex.com/data/file.jpg",
    file_size: int = 6,
    file_type: str = "image/jpeg",
    file_ext: str = "jpg",
    md5: str = "",
    sample_url: str = "https://cs.sankakucomplex.com/data/sample.jpg",
    preview_url: str = "https://cs.sankakucomplex.com/data/preview.jpg",
) -> SankakuPost:
    return SankakuPost(
        post_id=post_id,
        rating="s",
        status="active",
        width=1200,
        height=800,
        file_type=file_type,
        file_ext=file_ext,
        file_size=file_size,
        preview_url=preview_url,
        sample_url=sample_url,
        file_url=file_url,
        tag_names=("cat", "blue_eyes"),
        author="artist",
        created_at="1700000000",
        md5=md5,
        is_premium=False,
    )


class MediaDownloaderOfflineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.original_gate = download_engine.MEDIA_REQUEST_GATE
        gate_patch = mock.patch("download_engine.MEDIA_REQUEST_GATE", ImmediateGate())
        gate_patch.start()
        self.addCleanup(gate_patch.stop)

    def _downloader(
        self,
        post: SankakuPost,
        *responses: FakeMediaResponse,
        save_metadata: bool = False,
        stop_event: threading.Event | None = None,
        max_retries: int = 0,
        prefer_original: bool = True,
    ) -> tuple[MediaDownloader, FakeAPI, FakeMediaSession]:
        api = FakeAPI(post)
        session = FakeMediaSession(list(responses))
        downloader = MediaDownloader(
            api,
            self.temp_dir.name,
            timeout=10,
            max_retries=max_retries,
            prefer_original=prefer_original,
            save_metadata=save_metadata,
            stop_event=stop_event,
            session_factory=lambda: session,
        )
        self.addCleanup(downloader.close)
        return downloader, api, session

    def _paths(self, post_id: str = "Post_1") -> tuple[str, str, str]:
        final_path = os.path.join(self.temp_dir.name, f"{post_id}.jpg")
        part_path = os.path.join(self.temp_dir.name, f"{post_id}.download.part")
        return final_path, part_path, part_path + ".state.json"

    def _write_state(
        self,
        *,
        post_id: str = "Post_1",
        variant: str = "original",
        declared_type: str = "image/jpeg",
        expected_size: int = 6,
        expected_md5: str = "",
        etag: str = '"v1"',
        last_modified: str = "",
        total_size: int = 6,
    ) -> str:
        _final_path, _part_path, state_path = self._paths(post_id)
        payload = {
            "schema_version": 2,
            "post_id": post_id,
            "variant": variant,
            "declared_type": declared_type,
            "expected_size": expected_size,
            "expected_md5": expected_md5,
            "etag": etag,
            "last_modified": last_modified,
            "total_size": total_size,
        }
        with open(state_path, "w", encoding="ascii") as file_obj:
            json.dump(payload, file_obj)
        return state_path

    def _write_sidecar(
        self,
        media_path: str,
        payload: bytes,
        *,
        post_id: str = "Post_1",
        variant: str = "sample",
        content_type: str = "image/jpeg",
        extension: str = "jpg",
        mutate: dict[str, object] | None = None,
    ) -> str:
        sidecar = {
            "schema_version": 2,
            "post_id": post_id,
            "variant": variant,
            "filename": os.path.basename(media_path),
            "content_type": content_type,
            "extension": extension,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "post": {
                "rating": "s",
                "status": "active",
                "width": 1200,
                "height": 800,
                "tags": ["cat"],
                "author": "artist",
                "created_at": "1700000000",
                "is_premium": False,
            },
        }
        if mutate:
            sidecar.update(mutate)
        sidecar_path = media_path + ".json"
        with open(sidecar_path, "w", encoding="utf-8") as file_obj:
            json.dump(sidecar, file_obj)
        return sidecar_path

    def _make_directory_symlink(self, target: str, link: str) -> None:
        try:
            os.symlink(target, link, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(
                f"directory symlinks are unavailable: {type(exc).__name__}"
            )

    def _retarget_directory_symlink(self, link: str, target: str) -> None:
        try:
            os.unlink(link)
        except IsADirectoryError:
            os.rmdir(link)
        self._make_directory_symlink(target, link)

    def test_direct_media_url_must_be_allowlisted(self):
        downloader, api, session = self._downloader(
            _post(file_url="https://evil.example/file.jpg")
        )

        with self.assertRaisesRegex(DownloadError, "不受信任"):
            downloader.download("Post_1")

        self.assertEqual(api.post_ids, ["Post_1"])
        self.assertEqual(session.gets, [])
        self.assertEqual(session.headers["Accept-Encoding"], "identity")
        self.assertIn(
            "https://github.com/aaAarJimedes/SankakuSyncer_Portable",
            session.headers["User-Agent"],
        )
        self.assertEqual(
            os.listdir(self.temp_dir.name),
            [download_engine._DOWNLOAD_LOCK_NAME],
        )

    def test_redirect_target_must_also_be_allowlisted(self):
        redirect = FakeMediaResponse(
            302, headers={"Location": "https://evil.example/stolen.jpg"}
        )
        downloader, _api, session = self._downloader(_post(), redirect)

        with self.assertRaisesRegex(DownloadError, "官方域名"):
            downloader.download("Post_1")

        self.assertTrue(redirect.closed)
        self.assertEqual(len(session.gets), 1)
        self.assertFalse(session.gets[0]["kwargs"]["allow_redirects"])
        self.assertEqual(
            os.listdir(self.temp_dir.name),
            [download_engine._DOWNLOAD_LOCK_NAME],
        )

    def test_pathological_content_length_is_a_domain_error_before_writing(self):
        cases = (
            ("", "无效 Content-Length"),
            (" 1", "无效 Content-Length"),
            ("-1", "无效 Content-Length"),
            ("\N{SUPERSCRIPT TWO}", "无效 Content-Length"),
            ("9" * 5000, "50 GiB"),
        )
        for value, message in cases:
            with self.subTest(message=message):
                response = FakeMediaResponse(
                    200,
                    headers={
                        "Content-Type": "image/jpeg",
                        "Content-Length": value,
                    },
                    chunks=[JPEG],
                )
                downloader, _api, _session = self._downloader(_post(), response)

                with self.assertRaisesRegex(DownloadError, message):
                    downloader.download("Post_1")

                self.assertTrue(response.closed)
                self.assertEqual(
                    os.listdir(self.temp_dir.name),
                    [download_engine._DOWNLOAD_LOCK_NAME],
                )

    def test_explicit_zero_content_length_cannot_accept_a_nonempty_body(self):
        response = FakeMediaResponse(
            200,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": "0",
            },
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)
        final_path, part_path, state_path = self._paths()

        with self.assertRaisesRegex(DownloadError, "超过声明长度"):
            downloader.download("Post_1")

        self.assertFalse(os.path.exists(final_path))
        self.assertEqual(os.path.getsize(part_path), 0)
        self.assertTrue(os.path.isfile(state_path))
        self.assertTrue(response.closed)

    def test_existing_part_is_resumed_with_matching_206(self):
        final_path, part_path, state_path = self._paths()
        with open(part_path, "wb") as file_obj:
            file_obj.write(JPEG[:3])
        expected_md5 = hashlib.md5(JPEG, usedforsecurity=False).hexdigest()
        self._write_state(expected_md5=expected_md5)
        response = FakeMediaResponse(
            206,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": "3",
                "Content-Range": "bytes 3-5/6",
                "ETag": '"v1"',
            },
            chunks=[JPEG[3:]],
        )
        downloader, _api, session = self._downloader(
            _post(md5=expected_md5), response
        )

        result = downloader.download("Post_1")

        with open(final_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG)
        self.assertTrue(result.resumed)
        self.assertFalse(result.already_present)
        self.assertEqual(result.size, 6)
        self.assertEqual(result.sha256, hashlib.sha256(JPEG).hexdigest())
        self.assertFalse(os.path.exists(part_path))
        self.assertFalse(os.path.exists(state_path))
        self.assertEqual(
            session.gets[0]["kwargs"]["headers"],
            {"Range": "bytes=3-", "If-Range": '"v1"'},
        )
        self.assertTrue(response.closed)

    def test_resume_rejects_concurrent_append_before_media_validation(self):
        _final_path, part_path, state_path = self._paths()
        with open(part_path, "wb") as file_obj:
            file_obj.write(JPEG[:3])
        self._write_state(variant="sample", expected_size=0, total_size=6)

        def append_same_suffix(_index: int) -> None:
            with open(part_path, "ab") as file_obj:
                file_obj.write(JPEG[3:])

        response = FakeMediaResponse(
            206,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": "3",
                "Content-Range": "bytes 3-5/6",
                "ETag": '"v1"',
            },
            chunks=[JPEG[3:]],
            before_chunk=append_same_suffix,
        )
        downloader, _api, _session = self._downloader(
            _post(), response, prefer_original=False
        )

        with self.assertRaisesRegex(DownloadError, "并发变化"):
            downloader.download("Post_1")

        self.assertFalse(
            os.path.exists(os.path.join(self.temp_dir.name, "Post_1.sample.jpg"))
        )
        self.assertEqual(os.path.getsize(part_path), 9)
        self.assertTrue(os.path.isfile(state_path))

    def test_200_response_to_range_request_restarts_instead_of_appending(self):
        _final_path, part_path, state_path = self._paths()
        with open(part_path, "wb") as file_obj:
            file_obj.write(b"stal")
        self._write_state(expected_size=5, total_size=5)
        response = FakeMediaResponse(
            200,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": "5",
                "ETag": '"v2"',
            },
            chunks=[JPEG_FIVE],
        )
        downloader, _api, session = self._downloader(_post(file_size=5), response)

        result = downloader.download("Post_1")

        with open(result.file_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG_FIVE)
        self.assertFalse(result.resumed)
        self.assertEqual(result.size, 5)
        self.assertEqual(
            session.gets[0]["kwargs"]["headers"],
            {"Range": "bytes=4-", "If-Range": '"v1"'},
        )
        self.assertTrue(os.path.isfile(part_path))
        self.assertTrue(os.path.isfile(state_path))
        self.assertTrue(response.closed)

    def test_completion_is_committed_with_one_atomic_no_replace_move(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG[:3], JPEG[3:]],
        )
        expected_md5 = hashlib.md5(JPEG, usedforsecurity=False).hexdigest()
        downloader, _api, _session = self._downloader(
            _post(md5=expected_md5), response
        )
        final_path = os.path.join(self.temp_dir.name, "Post_1.jpg")
        observed_commits: list[tuple[str, str]] = []
        real_commit = download_engine._publish_bound_media_name_no_replace

        def atomic_no_replace(
            root_token: int,
            descriptor: int,
            source: str,
            destination: str,
        ) -> None:
            observed_commits.append((source, destination))
            if destination == "Post_1.jpg":
                self.assertEqual(os.path.basename(source), source)
                self.assertEqual(os.path.basename(destination), destination)
                if os.name == "nt":
                    self.assertTrue(source.endswith(".part"))
                else:
                    self.assertTrue(source.endswith(".tmp"))
                self.assertFalse(os.path.exists(final_path))
                position = os.lseek(descriptor, 0, os.SEEK_CUR)
                os.lseek(descriptor, 0, os.SEEK_SET)
                self.assertEqual(os.read(descriptor, len(JPEG)), JPEG)
                os.lseek(descriptor, position, os.SEEK_SET)
            real_commit(root_token, descriptor, source, destination)

        def progress(_current: int, _total: int) -> None:
            self.assertFalse(os.path.exists(final_path))

        with mock.patch(
            "download_engine._publish_bound_media_name_no_replace",
            side_effect=atomic_no_replace,
        ):
            result = downloader.download("Post_1", progress=progress)

        final_commits = [pair for pair in observed_commits if pair[1] == "Post_1.jpg"]
        self.assertEqual(len(final_commits), 1)
        self.assertTrue(os.path.samefile(result.file_path, final_path))
        self.assertTrue(os.path.isfile(final_path))
        self.assertFalse(os.path.exists(self._paths()[1]))

    def test_append_after_inspection_is_rejected_before_publish(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)
        real_commit = downloader._commit_media_no_replace

        def append_then_commit(part_path: str, **kwargs):
            with open(part_path, "ab") as file_obj:
                file_obj.write(b"RACE_APPEND")
            return real_commit(part_path, **kwargs)

        with mock.patch.object(
            downloader,
            "_commit_media_no_replace",
            side_effect=append_then_commit,
        ):
            with self.assertRaisesRegex(DownloadError, "发布前被其他进程改变"):
                downloader.download("Post_1")

        final_path, part_path, state_path = self._paths()
        self.assertFalse(os.path.exists(final_path))
        self.assertFalse(os.path.exists(final_path + ".json"))
        with open(part_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG + b"RACE_APPEND")
        self.assertTrue(os.path.isfile(state_path))

    def test_same_metadata_part_replacement_is_rejected_before_publish(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)
        real_commit = downloader._commit_media_no_replace

        def replace_then_commit(part_path: str, **kwargs):
            before = os.stat(part_path)
            replacement = part_path + ".replacement"
            with open(replacement, "xb") as file_obj:
                file_obj.write(JPEG)
            os.utime(
                replacement,
                ns=(
                    getattr(before, "st_atime_ns", 0),
                    getattr(before, "st_mtime_ns", 0),
                ),
            )
            os.replace(replacement, part_path)
            return real_commit(part_path, **kwargs)

        with mock.patch.object(
            downloader,
            "_commit_media_no_replace",
            side_effect=replace_then_commit,
        ):
            with self.assertRaisesRegex(DownloadError, "发布前被其他进程改变"):
                downloader.download("Post_1")

        final_path, part_path, state_path = self._paths()
        self.assertFalse(os.path.exists(final_path))
        with open(part_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG)
        self.assertTrue(os.path.isfile(state_path))

    @unittest.skipUnless(os.name == "nt", "Windows share-mode regression")
    def test_protected_part_blocks_late_writer_during_publish(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)
        part_path = self._paths()[1]
        real_publish = download_engine._publish_bound_media_name_no_replace
        denied: list[OSError] = []

        def try_late_write(
            root_token: int,
            descriptor: int,
            source: str,
            destination: str,
        ) -> None:
            try:
                with open(part_path, "ab") as file_obj:
                    file_obj.write(b"RACE_APPEND")
            except OSError as exc:
                denied.append(exc)
            real_publish(root_token, descriptor, source, destination)

        with mock.patch(
            "download_engine._publish_bound_media_name_no_replace",
            side_effect=try_late_write,
        ):
            result = downloader.download("Post_1")

        self.assertEqual(len(denied), 1)
        with open(result.file_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG)

    @unittest.skipUnless(os.name == "nt", "Windows handle-bound rollback")
    def test_windows_post_rename_query_failure_restores_partial(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)
        real_named_identity = download_engine._win_named_download_identity
        injected = False

        def fail_final_query(root_token: int, name: str):
            nonlocal injected
            if name == "Post_1.jpg" and not injected:
                injected = True
                raise DownloadError("simulated final identity query failure")
            return real_named_identity(root_token, name)

        with mock.patch(
            "download_engine._win_named_download_identity",
            side_effect=fail_final_query,
        ):
            with self.assertRaisesRegex(DownloadError, "simulated final"):
                downloader.download("Post_1")

        final_path, part_path, state_path = self._paths()
        self.assertFalse(os.path.exists(final_path))
        with open(part_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG)
        self.assertTrue(os.path.isfile(state_path))

    @unittest.skipUnless(os.name == "nt", "Windows descriptor conversion")
    def test_windows_protected_descriptor_failure_preserves_partial(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)
        real_commit = downloader._commit_media_no_replace

        def fail_descriptor_conversion(part_path: str, **kwargs):
            with mock.patch.object(
                download_engine.msvcrt,
                "open_osfhandle",
                side_effect=OSError("simulated descriptor failure"),
            ):
                return real_commit(part_path, **kwargs)

        with mock.patch.object(
            downloader,
            "_commit_media_no_replace",
            side_effect=fail_descriptor_conversion,
        ):
            with self.assertRaisesRegex(DownloadError, "受保护描述符"):
                downloader.download("Post_1")

        final_path, part_path, state_path = self._paths()
        self.assertFalse(os.path.exists(final_path))
        with open(part_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG)
        self.assertTrue(os.path.isfile(state_path))

    @unittest.skipIf(os.name == "nt", "POSIX snapshot failure contract")
    def test_posix_snapshot_write_failure_preserves_partial(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)

        with mock.patch(
            "download_engine._write_all",
            side_effect=OSError("simulated snapshot write failure"),
        ):
            with self.assertRaisesRegex(DownloadError, "安全下载发布失败"):
                downloader.download("Post_1")

        final_path, part_path, state_path = self._paths()
        self.assertFalse(os.path.exists(final_path))
        self.assertTrue(os.path.isfile(part_path))
        self.assertTrue(os.path.isfile(state_path))
        self.assertFalse(
            any(
                name.startswith(".sankakusyncer-download-snapshot-")
                for name in os.listdir(self.temp_dir.name)
            )
        )

    @unittest.skipIf(os.name == "nt", "POSIX atomic rename contract")
    def test_posix_publish_never_depends_on_snapshot_unlink(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)
        real_unlink_owned = download_engine._posix_unlink_owned_name

        def reject_snapshot_unlink(root_token, name, expected, *, allowed_links):
            if name.startswith(".sankakusyncer-download-snapshot-"):
                raise AssertionError("published snapshots must be renamed atomically")
            return real_unlink_owned(
                root_token,
                name,
                expected,
                allowed_links=allowed_links,
            )

        with mock.patch(
            "download_engine._posix_unlink_owned_name",
            side_effect=reject_snapshot_unlink,
        ):
            result = downloader.download("Post_1")

        with open(result.file_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG)
        self.assertEqual(os.stat(result.file_path).st_nlink, 1)
        self.assertFalse(
            any(
                name.startswith(".sankakusyncer-download-snapshot-")
                for name in os.listdir(self.temp_dir.name)
            )
        )

    @unittest.skipIf(os.name == "nt", "POSIX generic no-clobber commit")
    def test_posix_generic_commit_uses_one_atomic_rename(self):
        source = os.path.join(self.temp_dir.name, ".metadata.unique.tmp")
        destination = os.path.join(self.temp_dir.name, "Post_1.jpg.json")
        with open(source, "xb") as file_obj:
            file_obj.write(b"metadata")

        with mock.patch.object(
            download_engine.os,
            "unlink",
            side_effect=AssertionError("no post-rename unlink is allowed"),
        ):
            download_engine._commit_file_no_replace(source, destination)

        self.assertFalse(os.path.exists(source))
        with open(destination, "rb") as file_obj:
            self.assertEqual(file_obj.read(), b"metadata")
        self.assertEqual(os.stat(destination).st_nlink, 1)

    @unittest.skipIf(os.name == "nt", "POSIX crash-recovery snapshot cleanup")
    def test_posix_stale_owned_snapshot_is_removed_under_directory_lease(self):
        stale_name = (
            ".sankakusyncer-download-snapshot-"
            "0123456789abcdef0123456789abcdef.tmp"
        )
        stale_path = os.path.join(self.temp_dir.name, stale_name)
        near_match = os.path.join(
            self.temp_dir.name,
            ".sankakusyncer-download-snapshot-not-owned.tmp",
        )
        with open(stale_path, "xb") as file_obj:
            file_obj.write(b"interrupted-snapshot")
        with open(near_match, "xb") as file_obj:
            file_obj.write(b"unrelated")
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)

        result = downloader.download("Post_1")

        self.assertTrue(os.path.isfile(result.file_path))
        self.assertFalse(os.path.exists(stale_path))
        with open(near_match, "rb") as file_obj:
            self.assertEqual(file_obj.read(), b"unrelated")

    def test_part_with_extra_hardlink_is_rejected(self):
        final_path, part_path, state_path = self._paths()
        with open(part_path, "wb") as file_obj:
            file_obj.write(JPEG[:3])
        self._write_state()
        alias_path = os.path.join(self.temp_dir.name, "part-owner-alias.bin")
        os.link(part_path, alias_path)
        response = FakeMediaResponse(
            206,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": "3",
                "Content-Range": "bytes 3-5/6",
                "ETag": '"v1"',
            },
            chunks=[JPEG[3:]],
        )
        downloader, _api, session = self._downloader(_post(), response)

        with self.assertRaisesRegex(DownloadError, "多链接文件"):
            downloader.download("Post_1")

        self.assertEqual(session.gets, [])
        self.assertFalse(os.path.exists(final_path))
        with open(alias_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG[:3])
        self.assertTrue(os.path.isfile(part_path))
        self.assertTrue(os.path.isfile(state_path))

    def test_final_name_replacement_before_return_is_detected(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)
        final_path = self._paths()[0]
        displaced_path = final_path + ".displaced"
        real_result = downloader._result
        denied: list[OSError] = []

        def replace_final(*args, **kwargs):
            try:
                os.rename(final_path, displaced_path)
            except OSError as exc:
                denied.append(exc)
                return real_result(*args, **kwargs)
            with open(final_path, "xb") as file_obj:
                file_obj.write(b"replacement-owner")
            return real_result(*args, **kwargs)

        with mock.patch.object(downloader, "_result", side_effect=replace_final):
            if os.name == "nt":
                result = downloader.download("Post_1")
            else:
                with self.assertRaisesRegex(DownloadError, "返回前被替换"):
                    downloader.download("Post_1")

        if os.name == "nt":
            self.assertEqual(len(denied), 1)
            self.assertFalse(os.path.exists(displaced_path))
            with open(result.file_path, "rb") as file_obj:
                self.assertEqual(file_obj.read(), JPEG)
        else:
            with open(final_path, "rb") as file_obj:
                self.assertEqual(file_obj.read(), b"replacement-owner")
            with open(displaced_path, "rb") as file_obj:
                self.assertEqual(file_obj.read(), JPEG)

    @unittest.skipUnless(os.name == "nt", "Windows final-name share contract")
    def test_windows_final_cannot_be_replaced_between_lease_checks(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)
        final_path = self._paths()[0]
        displaced_path = final_path + ".displaced"
        real_named_identity = download_engine._win_named_download_identity
        final_queries = 0
        denied: list[OSError] = []

        def identity_then_replace(root_token: int, name: str):
            nonlocal final_queries
            identity = real_named_identity(root_token, name)
            if name == "Post_1.jpg":
                final_queries += 1
                if final_queries == 2:
                    try:
                        os.rename(final_path, displaced_path)
                        with open(final_path, "xb") as file_obj:
                            file_obj.write(JPEG_ALT)
                    except OSError as exc:
                        denied.append(exc)
            return identity

        with mock.patch(
            "download_engine._win_named_download_identity",
            side_effect=identity_then_replace,
        ):
            result = downloader.download("Post_1")

        self.assertEqual(len(denied), 1)
        self.assertGreaterEqual(final_queries, 3)
        self.assertFalse(os.path.exists(displaced_path))
        with open(result.file_path, "rb") as file_obj:
            published = file_obj.read()
        self.assertEqual(published, JPEG)
        self.assertEqual(result.sha256, hashlib.sha256(published).hexdigest())

    def test_ancestor_symlink_retarget_does_not_redirect_download_writes(self):
        root_a = os.path.join(self.temp_dir.name, "root-a")
        root_b = os.path.join(self.temp_dir.name, "root-b")
        output_a = os.path.join(root_a, "Downloads")
        output_b = os.path.join(root_b, "Downloads")
        os.makedirs(output_a)
        os.makedirs(output_b)
        alias = os.path.join(self.temp_dir.name, "alias")
        self._make_directory_symlink(root_a, alias)
        configured_output = os.path.join(alias, "Downloads")

        class RetargetingAPI(FakeAPI):
            def get_post(inner_self, post_id: str) -> SankakuPost:
                self._retarget_directory_symlink(alias, root_b)
                return super().get_post(post_id)

        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        api = RetargetingAPI(_post())
        session = FakeMediaSession([response])
        downloader = MediaDownloader(
            api,
            configured_output,
            timeout=10,
            max_retries=0,
            save_metadata=False,
            session_factory=lambda: session,
        )
        self.addCleanup(downloader.close)

        with self.assertRaisesRegex(DownloadError, "租约在操作期间失效"):
            downloader.download("Post_1")

        self.assertEqual(sorted(os.listdir(output_b)), [])
        self.assertTrue(os.path.isfile(os.path.join(output_a, "Post_1.jpg")))
        self.assertTrue(
            os.path.isfile(
                os.path.join(output_a, download_engine._DOWNLOAD_LOCK_NAME)
            )
        )

    def test_retarget_after_publish_cannot_delete_or_describe_new_root(self):
        root_a = os.path.join(self.temp_dir.name, "late-root-a")
        root_b = os.path.join(self.temp_dir.name, "late-root-b")
        output_a = os.path.join(root_a, "Downloads")
        output_b = os.path.join(root_b, "Downloads")
        os.makedirs(output_a)
        os.makedirs(output_b)
        alias = os.path.join(self.temp_dir.name, "late-alias")
        self._make_directory_symlink(root_a, alias)
        configured_output = os.path.join(alias, "Downloads")
        decoy_state = os.path.join(
            output_b, "Post_1.download.part.state.json"
        )
        decoy_payload: list[bytes] = []

        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        api = FakeAPI(_post())
        session = FakeMediaSession([response])
        downloader = MediaDownloader(
            api,
            configured_output,
            timeout=10,
            max_retries=0,
            save_metadata=True,
            session_factory=lambda: session,
        )
        self.addCleanup(downloader.close)
        real_commit = downloader._commit_media_no_replace

        def publish_then_retarget(part_path: str, **kwargs):
            lease = real_commit(part_path, **kwargs)
            source_state = part_path + ".state.json"
            with open(source_state, "rb") as file_obj:
                compatible_state = file_obj.read()
            with open(decoy_state, "xb") as file_obj:
                file_obj.write(compatible_state)
            decoy_payload.append(compatible_state)
            self._retarget_directory_symlink(alias, root_b)
            return lease

        with mock.patch.object(
            downloader,
            "_commit_media_no_replace",
            side_effect=publish_then_retarget,
        ):
            with self.assertRaisesRegex(DownloadError, "租约在操作期间失效"):
                downloader.download("Post_1")

        with open(decoy_state, "rb") as file_obj:
            self.assertEqual(file_obj.read(), decoy_payload[0])
        self.assertFalse(os.path.exists(os.path.join(output_b, "Post_1.jpg.json")))
        self.assertTrue(os.path.isfile(os.path.join(output_a, "Post_1.jpg")))
        self.assertTrue(os.path.isfile(os.path.join(output_a, "Post_1.jpg.json")))

    def test_metadata_contains_neither_urls_nor_credentials(self):
        secret_url = (
            "https://cs.sankakucomplex.com/data/file.jpg"
            "?e=1700000000&m=MEDIA_URL_SECRET"
        )
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, api, session = self._downloader(
            _post(file_url=secret_url), response, save_metadata=True
        )

        result = downloader.download("Post_1")

        metadata_path = result.file_path + ".json"
        with open(metadata_path, "r", encoding="utf-8") as file_obj:
            raw_metadata = file_obj.read()
        payload = json.loads(raw_metadata)
        self.assertEqual(payload["post_id"], "Post_1")
        self.assertEqual(payload["sha256"], result.sha256)
        with open(result.file_path, "rb") as file_obj:
            published_bytes = file_obj.read()
        self.assertEqual(result.size, len(published_bytes))
        self.assertEqual(result.sha256, hashlib.sha256(published_bytes).hexdigest())
        self.assertEqual(payload["size"], len(published_bytes))
        self.assertEqual(payload["sha256"], hashlib.sha256(published_bytes).hexdigest())
        lowered_keys: list[str] = []

        def collect_keys(value) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    lowered_keys.append(str(key).lower())
                    collect_keys(child)
            elif isinstance(value, list):
                for child in value:
                    collect_keys(child)

        collect_keys(payload)
        self.assertFalse(any("url" in key for key in lowered_keys))
        self.assertFalse(any("token" in key for key in lowered_keys))
        for secret in (
            "MEDIA_URL_SECRET",
            api.access_token,
            api.username,
            api.password,
            secret_url,
        ):
            self.assertNotIn(secret, raw_metadata)
        self.assertNotIn("Authorization", session.headers)
        self.assertNotIn("Authorization", session.gets[0]["kwargs"]["headers"])

    def test_untrusted_json_extension_cannot_overwrite_verified_media(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(
            _post(file_ext="json", file_type="image/jpeg"),
            response,
            save_metadata=True,
        )

        result = downloader.download("Post_1")

        self.assertTrue(result.file_path.endswith("Post_1.jpg"))
        with open(result.file_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG)
        metadata_path = result.file_path + ".json"
        self.assertNotEqual(result.file_path, metadata_path)
        with open(metadata_path, "r", encoding="utf-8") as file_obj:
            payload = json.load(file_obj)
        self.assertEqual(payload["filename"], "Post_1.jpg")

    def test_html_media_response_is_rejected_without_committing_a_file(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "text/html", "Content-Length": "31"},
            chunks=[b"<html><title>Login</title></html>"],
        )
        downloader, _api, _session = self._downloader(_post(), response)

        with self.assertRaisesRegex(DownloadError, "网页或错误信息"):
            downloader.download("Post_1")

        self.assertTrue(response.closed)
        self.assertFalse(os.path.exists(os.path.join(self.temp_dir.name, "Post_1.jpg")))
        self.assertFalse(
            os.path.exists(os.path.join(self.temp_dir.name, "Post_1.download.part"))
        )

    def test_non_identity_content_encoding_is_rejected(self):
        response = FakeMediaResponse(
            200,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Encoding": "gzip",
                "Content-Length": "6",
            },
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)

        with self.assertRaisesRegex(DownloadError, "压缩编码"):
            downloader.download("Post_1")

        self.assertFalse(os.path.exists(self._paths()[0]))
        self.assertFalse(os.path.exists(self._paths()[1]))

    def test_existing_final_part_and_state_reparse_paths_are_rejected(self):
        final_path, part_path, state_path = self._paths()
        real_lstat = os.lstat
        fake_reparse = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_file_attributes=getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
            ),
            st_size=0,
            st_dev=1,
            st_ino=1,
            st_nlink=1,
        )

        for unsafe_path in (final_path, part_path, state_path):
            with self.subTest(unsafe_path=unsafe_path):
                def selective_lstat(path: str):
                    if os.path.normcase(os.path.basename(path)) == os.path.normcase(
                        os.path.basename(unsafe_path)
                    ):
                        return fake_reparse
                    return real_lstat(path)

                downloader, _api, session = self._downloader(_post())
                with mock.patch(
                    "download_engine.os.lstat", side_effect=selective_lstat
                ), mock.patch(
                    "download_engine.os.listdir",
                    return_value=[os.path.basename(unsafe_path)],
                ):
                    with self.assertRaisesRegex(DownloadError, "链接或重解析点"):
                        downloader.download("Post_1")
                self.assertEqual(session.gets, [])

    def test_existing_sidecar_reparse_path_is_rejected_before_network(self):
        media_path = os.path.join(self.temp_dir.name, "Post_1.sample.jpg")
        with open(media_path, "wb") as file_obj:
            file_obj.write(JPEG)
        sidecar_path = media_path + ".json"
        real_lstat = os.lstat
        fake_reparse = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_file_attributes=getattr(
                stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400
            ),
            st_size=10,
            st_dev=1,
            st_ino=1,
            st_nlink=1,
        )

        def selective_lstat(path: str):
            if os.path.normcase(os.path.basename(path)) == os.path.normcase(
                os.path.basename(sidecar_path)
            ):
                return fake_reparse
            return real_lstat(path)

        downloader, _api, session = self._downloader(
            _post(), prefer_original=False
        )
        with mock.patch(
            "download_engine.os.lstat", side_effect=selective_lstat
        ):
            with self.assertRaisesRegex(DownloadError, "链接或重解析点"):
                downloader.download("Post_1")
        self.assertEqual(session.gets, [])

    def test_new_part_open_uses_exclusive_creation(self):
        _final_path, part_path, _state_path = self._paths()
        with mock.patch(
            "download_engine.os.open", side_effect=FileExistsError("collision")
        ) as open_mock:
            with self.assertRaisesRegex(DownloadError, "其他进程占用"):
                download_engine._open_part_for_write(
                    part_path,
                    append=False,
                    expected_size=0,
                )

        flags = open_mock.call_args.args[1]
        self.assertTrue(flags & os.O_CREAT)
        self.assertTrue(flags & os.O_EXCL)

    def test_append_rejects_lstat_fstat_identity_change(self):
        _final_path, part_path, _state_path = self._paths()
        with open(part_path, "wb") as file_obj:
            file_obj.write(JPEG[:3])

        with mock.patch("download_engine._same_file_identity", return_value=False):
            with self.assertRaisesRegex(DownloadError, "打开期间被替换或改变"):
                download_engine._open_part_for_write(
                    part_path,
                    append=True,
                    expected_size=3,
                )

        with open(part_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG[:3])

    def test_part_without_authenticated_state_is_restarted(self):
        _final_path, part_path, _state_path = self._paths()
        with open(part_path, "wb") as file_obj:
            file_obj.write(JPEG[:3])
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, session = self._downloader(_post(), response)

        result = downloader.download("Post_1")

        self.assertFalse(result.resumed)
        self.assertEqual(session.gets[0]["kwargs"]["headers"], {})
        with open(result.file_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG)

    def test_weak_etag_state_is_not_used_for_if_range(self):
        _final_path, part_path, _state_path = self._paths()
        with open(part_path, "wb") as file_obj:
            file_obj.write(JPEG[:3])
        self._write_state(etag='W/"v1"')
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, session = self._downloader(_post(), response)

        result = downloader.download("Post_1")

        self.assertFalse(result.resumed)
        self.assertEqual(session.gets[0]["kwargs"]["headers"], {})

    def test_valid_last_modified_is_used_as_if_range(self):
        _final_path, part_path, _state_path = self._paths()
        with open(part_path, "wb") as file_obj:
            file_obj.write(JPEG[:3])
        self._write_state(etag="", last_modified=HTTP_DATE)
        response = FakeMediaResponse(
            206,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": "3",
                "Content-Range": "bytes 3-5/6",
                "Last-Modified": HTTP_DATE,
            },
            chunks=[JPEG[3:]],
        )
        downloader, _api, session = self._downloader(_post(), response)

        result = downloader.download("Post_1")

        self.assertTrue(result.resumed)
        self.assertEqual(
            session.gets[0]["kwargs"]["headers"],
            {"Range": "bytes=3-", "If-Range": HTTP_DATE},
        )

    def test_resume_state_binds_declared_type_total_and_validators(self):
        cases = (
            (
                {"Content-Type": "image/png", "ETag": '"v1"',
                 "Content-Range": "bytes 3-5/6", "Content-Length": "3"},
                "Content-Type 已变化",
            ),
            (
                {"Content-Type": "image/jpeg", "ETag": '"v1"',
                 "Content-Range": "bytes 3-6/7", "Content-Length": "4"},
                "总长度已变化",
            ),
            (
                {"Content-Type": "image/jpeg", "ETag": '"v2"',
                 "Content-Range": "bytes 3-5/6", "Content-Length": "3"},
                "ETag 已变化",
            ),
            (
                {"Content-Type": "image/jpeg",
                 "Content-Range": "bytes 3-5/6", "Content-Length": "3"},
                "ETag 已变化",
            ),
        )
        for index, (headers, error) in enumerate(cases):
            with self.subTest(error=error, index=index):
                post_id = f"Post_state_{index}"
                _final, part_path, state_path = self._paths(post_id)
                with open(part_path, "wb") as file_obj:
                    file_obj.write(JPEG[:3])
                self._write_state(post_id=post_id)
                response = FakeMediaResponse(206, headers=headers, chunks=[JPEG[3:]])
                downloader, _api, _session = self._downloader(
                    _post(post_id), response
                )

                with self.assertRaisesRegex(DownloadError, error):
                    downloader.download(post_id)

                with open(part_path, "rb") as file_obj:
                    self.assertEqual(file_obj.read(), JPEG[:3])
                self.assertTrue(os.path.isfile(state_path))

    def test_mismatched_content_range_is_rejected_and_existing_part_is_preserved(self):
        final_path, part_path, state_path = self._paths()
        with open(part_path, "wb") as file_obj:
            file_obj.write(JPEG[:3])
        self._write_state()
        response = FakeMediaResponse(
            206,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": "3",
                "Content-Range": "bytes 2-4/6",
                "ETag": '"v1"',
            },
            chunks=[b"abc"],
        )
        downloader, _api, _session = self._downloader(_post(), response)

        with self.assertRaisesRegex(DownloadError, "不匹配的续传范围"):
            downloader.download("Post_1")

        self.assertFalse(os.path.exists(final_path))
        self.assertTrue(os.path.isfile(part_path))
        self.assertTrue(os.path.isfile(state_path))

    def test_malformed_content_range_is_rejected_and_existing_part_is_preserved(self):
        _final_path, part_path, state_path = self._paths()
        with open(part_path, "wb") as file_obj:
            file_obj.write(JPEG[:3])
        self._write_state()
        response = FakeMediaResponse(
            206,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": "3",
                "Content-Range": "bytes not-a-range",
            },
            chunks=[b"abc"],
        )
        downloader, _api, _session = self._downloader(_post(), response)

        with self.assertRaisesRegex(DownloadError, "无效 Content-Range"):
            downloader.download("Post_1")

        self.assertTrue(os.path.isfile(part_path))
        self.assertTrue(os.path.isfile(state_path))

    def test_pathological_content_range_is_a_domain_error_and_preserves_resume(self):
        _final_path, part_path, state_path = self._paths()
        with open(part_path, "wb") as file_obj:
            file_obj.write(JPEG[:3])
        self._write_state()
        response = FakeMediaResponse(
            206,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": "3",
                "Content-Range": f"bytes 3-5/{'9' * 5000}",
            },
            chunks=[JPEG[3:]],
        )
        downloader, _api, _session = self._downloader(_post(), response)

        with self.assertRaisesRegex(DownloadError, "无效 Content-Range"):
            downloader.download("Post_1")

        self.assertTrue(response.closed)
        with open(part_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG[:3])
        self.assertTrue(os.path.isfile(state_path))

    def test_unsolicited_partial_response_is_rejected(self):
        response = FakeMediaResponse(
            206,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": "6",
                "Content-Range": "bytes 0-5/6",
            },
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)

        with self.assertRaisesRegex(DownloadError, "未请求续传"):
            downloader.download("Post_1")

        self.assertFalse(os.path.exists(self._paths()[0]))

    def test_original_expected_size_mismatch_is_rejected(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "5"},
            chunks=[JPEG_FIVE],
        )
        downloader, _api, _session = self._downloader(_post(file_size=6), response)

        with self.assertRaisesRegex(DownloadError, "长度与站点元数据不匹配"):
            downloader.download("Post_1")

        self.assertFalse(os.path.exists(self._paths()[0]))
        self.assertFalse(os.path.exists(self._paths()[1]))

    def test_original_expected_md5_mismatch_is_rejected(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(
            _post(md5="0" * 32), response
        )

        with self.assertRaisesRegex(DownloadError, "MD5 校验失败"):
            downloader.download("Post_1")

        self.assertFalse(os.path.exists(self._paths()[0]))
        self.assertTrue(os.path.exists(self._paths()[1]))

    def test_original_integrity_fields_do_not_apply_to_sample_fallback(self):
        response = FakeMediaResponse(
            200,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": str(len(JPEG_COMPLETE)),
            },
            chunks=[JPEG_COMPLETE],
        )
        downloader, _api, _session = self._downloader(
            _post(file_url="", file_size=999, md5="0" * 32), response
        )

        result = downloader.download("Post_1")

        self.assertEqual(result.size, len(JPEG_COMPLETE))

    def test_valid_existing_file_is_verified_and_metadata_is_supplemented(self):
        final_path, _part_path, _state_path = self._paths()
        with open(final_path, "wb") as file_obj:
            file_obj.write(JPEG)
        expected_md5 = hashlib.md5(JPEG, usedforsecurity=False).hexdigest()
        downloader, _api, session = self._downloader(
            _post(md5=expected_md5), save_metadata=True
        )

        result = downloader.download("Post_1")

        self.assertTrue(result.already_present)
        self.assertEqual(session.gets, [])
        metadata_path = final_path + ".json"
        self.assertTrue(os.path.isfile(metadata_path))
        with open(metadata_path, "r", encoding="utf-8") as file_obj:
            payload = json.load(file_obj)
        self.assertEqual(payload["sha256"], hashlib.sha256(JPEG).hexdigest())

    def test_invalid_existing_file_is_never_replaced_by_verified_download(self):
        final_path, _part_path, _state_path = self._paths()
        with open(final_path, "wb") as file_obj:
            file_obj.write(b"<html>")
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG_ALT],
        )
        downloader, _api, session = self._downloader(_post(), response)

        result = downloader.download("Post_1")

        self.assertFalse(result.already_present)
        self.assertEqual(len(session.gets), 1)
        with open(final_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), b"<html>")
        self.assertTrue(result.file_path.endswith("Post_1 (1).jpg"))
        with open(result.file_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG_ALT)

    def test_html_and_json_disguised_as_images_fail_magic_validation(self):
        for payload in (b"<html>login</html>", b'{"error":"login"}'):
            with self.subTest(payload=payload):
                response = FakeMediaResponse(
                    200,
                    headers={
                        "Content-Type": "image/jpeg",
                        "Content-Length": str(len(payload)),
                    },
                    chunks=[payload],
                )
                downloader, _api, _session = self._downloader(
                    _post(file_size=len(payload)), response
                )

                with self.assertRaisesRegex(DownloadError, "网页或 JSON"):
                    downloader.download("Post_1")

                self.assertFalse(os.path.exists(self._paths()[0]))
                self.assertTrue(os.path.exists(self._paths()[1]))

    def test_signed_media_denial_is_per_item_download_error(self):
        for status_code in (401, 403):
            with self.subTest(status_code=status_code):
                response = FakeMediaResponse(status_code)
                downloader, _api, _session = self._downloader(_post(), response)

                with self.assertRaises(MediaAccessDeniedError) as raised:
                    downloader.download("Post_1")

                self.assertIsInstance(raised.exception, DownloadError)
                self.assertTrue(response.closed)

    def test_long_rate_limit_raises_domain_error_without_retry_sleep(self):
        deferred: list[float] = []

        class RateGate(ImmediateGate):
            def defer(self, seconds: float) -> None:
                deferred.append(seconds)

        response = FakeMediaResponse(429, headers={"Retry-After": "601"})
        downloader, _api, session = self._downloader(
            _post(), response, max_retries=3
        )

        with mock.patch("download_engine.MEDIA_REQUEST_GATE", RateGate()):
            with self.assertRaises(RateLimitError):
                downloader.download("Post_1")

        self.assertEqual(len(session.gets), 1)
        self.assertEqual(deferred, [601.0])
        self.assertTrue(response.closed)

    def test_non_finite_rate_limit_uses_default_without_retrying(self):
        deferred: list[float] = []

        class RateGate(ImmediateGate):
            def defer(self, seconds: float) -> None:
                deferred.append(seconds)

        response = FakeMediaResponse(429, headers={"Retry-After": "NaN"})
        downloader, _api, session = self._downloader(
            _post(), response, max_retries=3
        )

        with mock.patch("download_engine.MEDIA_REQUEST_GATE", RateGate()):
            with self.assertRaises(RateLimitError):
                downloader.download("Post_1")

        self.assertEqual(len(session.gets), 1)
        self.assertEqual(deferred, [600.0])
        self.assertTrue(response.closed)

    def test_metadata_failure_is_a_warning_after_media_success(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(
            _post(), response, save_metadata=True
        )

        with mock.patch.object(
            downloader,
            "_save_metadata",
            side_effect=OSError("simulated metadata failure"),
        ):
            result = downloader.download("Post_1")

        self.assertIn("元数据写入失败", result.metadata_warning)
        self.assertTrue(os.path.isfile(result.file_path))
        self.assertEqual(result.size, len(JPEG))

    def test_directory_lease_wait_is_cancellable_before_metadata_fetch(self):
        stop_event = ObservedStopEvent()
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, api, session = self._downloader(
            _post(), response, stop_event=stop_event
        )
        started = threading.Event()
        outcome: dict[str, object] = {}

        def run_download() -> None:
            started.set()
            try:
                outcome["result"] = downloader.download("Post_1")
            except BaseException as exc:
                outcome["error"] = exc

        holder = download_engine.BoundProcessLock(
            self.temp_dir.name,
            download_engine._DOWNLOAD_LOCK_NAME,
        )
        with holder:
            thread = threading.Thread(target=run_download)
            thread.start()
            self.assertTrue(started.wait(1.0))
            self.assertTrue(stop_event.wait_entered.wait(1.0))
            self.assertTrue(thread.is_alive())
            self.assertEqual(api.post_ids, [])
            self.assertEqual(session.gets, [])
            stop_event.set()
            thread.join(2.0)
            self.assertFalse(thread.is_alive())

        self.assertIsInstance(outcome.get("error"), CancelledError)
        self.assertNotIn("result", outcome)
        self.assertEqual(
            os.listdir(self.temp_dir.name),
            [download_engine._DOWNLOAD_LOCK_NAME],
        )

    def test_metadata_is_fetched_only_after_directory_lease_acquisition(self):
        stop_event = ObservedStopEvent()
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, api, session = self._downloader(
            _post(), response, stop_event=stop_event
        )
        started = threading.Event()
        outcome: dict[str, object] = {}

        def run_download() -> None:
            started.set()
            try:
                outcome["result"] = downloader.download("Post_1")
            except BaseException as exc:
                outcome["error"] = exc

        holder = download_engine.BoundProcessLock(
            self.temp_dir.name,
            download_engine._DOWNLOAD_LOCK_NAME,
        )
        with holder:
            thread = threading.Thread(target=run_download)
            thread.start()
            self.assertTrue(started.wait(1.0))
            self.assertTrue(stop_event.wait_entered.wait(1.0))
            self.assertTrue(thread.is_alive())
            self.assertEqual(api.post_ids, [])
            self.assertEqual(session.gets, [])

        thread.join(3.0)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", outcome)
        self.assertIsInstance(outcome.get("result"), DownloadResult)
        self.assertEqual(api.post_ids, ["Post_1"])
        self.assertEqual(len(session.gets), 1)

    def test_existing_download_lock_bytes_are_preserved(self):
        lock_path = os.path.join(
            self.temp_dir.name,
            download_engine._DOWNLOAD_LOCK_NAME,
        )
        sentinel = b"existing-owner-metadata"
        with open(lock_path, "wb") as file_obj:
            file_obj.write(sentinel)
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)

        result = downloader.download("Post_1")

        self.assertTrue(os.path.isfile(result.file_path))
        with open(lock_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), sentinel)

    def test_unsafe_download_lock_object_fails_without_waiting_or_network(self):
        lock_path = os.path.join(
            self.temp_dir.name,
            download_engine._DOWNLOAD_LOCK_NAME,
        )
        os.mkdir(lock_path)
        downloader, api, session = self._downloader(_post())

        with self.assertRaisesRegex(DownloadError, "无法安全锁定"):
            downloader.download("Post_1")

        self.assertEqual(api.post_ids, [])
        self.assertEqual(session.gets, [])

    def test_directory_lease_covers_metadata_and_result_creation(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(
            _post(), response, save_metadata=True
        )
        real_save = downloader._save_metadata
        real_result = downloader._result
        observed: list[str] = []

        def assert_busy(phase: str) -> None:
            contender = download_engine.BoundProcessLock(
                self.temp_dir.name,
                download_engine._DOWNLOAD_LOCK_NAME,
            )
            with self.assertRaises(download_engine.BoundProcessLockBusy):
                contender.__enter__()
            observed.append(phase)

        def save_with_probe(*args, **kwargs):
            assert_busy("metadata")
            return real_save(*args, **kwargs)

        def result_with_probe(*args, **kwargs):
            assert_busy("result")
            return real_result(*args, **kwargs)

        with mock.patch.object(
            downloader, "_save_metadata", side_effect=save_with_probe
        ), mock.patch.object(
            downloader, "_result", side_effect=result_with_probe
        ):
            result = downloader.download("Post_1")

        self.assertEqual(observed, ["metadata", "result"])
        self.assertTrue(os.path.isfile(result.file_path))
        with download_engine.BoundProcessLock(
            self.temp_dir.name,
            download_engine._DOWNLOAD_LOCK_NAME,
        ):
            pass

    def test_successful_body_translates_directory_lease_exit_failure(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)
        real_exit = download_engine.BoundProcessLock.__exit__

        def release_then_fail(lock, exc_type, exc, traceback):
            real_exit(lock, exc_type, exc, traceback)
            raise download_engine.BoundProcessLockError(
                "process lock is unavailable"
            )

        with mock.patch.object(
            download_engine.BoundProcessLock,
            "__exit__",
            new=release_then_fail,
        ):
            with self.assertRaisesRegex(DownloadError, "租约在操作期间失效"):
                downloader.download("Post_1")

        self.assertTrue(os.path.isfile(self._paths()[0]))
        with download_engine.BoundProcessLock(
            self.temp_dir.name,
            download_engine._DOWNLOAD_LOCK_NAME,
        ):
            pass

    def test_cancellation_is_checked_immediately_before_commit(self):
        stop_event = threading.Event()
        response = FakeMediaResponse(
            200,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": "6",
                "ETag": '"v1"',
            },
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(
            _post(), response, stop_event=stop_event
        )
        real_inspect = download_engine._inspect_media_file

        def inspect_then_cancel(path: str, event: threading.Event):
            inspection = real_inspect(path, event)
            stop_event.set()
            return inspection

        with mock.patch(
            "download_engine._inspect_media_file", side_effect=inspect_then_cancel
        ):
            with self.assertRaises(CancelledError):
                downloader.download("Post_1")

        final_path, part_path, state_path = self._paths()
        self.assertFalse(os.path.exists(final_path))
        self.assertTrue(os.path.isfile(part_path))
        self.assertTrue(os.path.isfile(state_path))

    def test_downloads_use_the_process_shared_media_gate(self):
        calls: list[tuple[threading.Event, float]] = []

        class RecordingGate:
            @contextmanager
            def slot(
                self,
                stop_event: threading.Event,
                *,
                min_interval: float = 0.0,
            ):
                calls.append((stop_event, min_interval))
                yield

        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)

        with mock.patch("download_engine.MEDIA_REQUEST_GATE", RecordingGate()):
            downloader.download("Post_1")

        self.assertIs(self.original_gate, request_gate.MEDIA_REQUEST_GATE)
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0][0], downloader.stop_event)
        self.assertGreater(calls[0][1], 0.0)

    def test_sample_and_preview_are_first_class_and_use_detected_jpeg_names(self):
        cases = (
            (
                "Post_GIF",
                _post(
                    "Post_GIF",
                    file_type="image/gif",
                    file_ext="gif",
                    file_size=999,
                    md5="0" * 32,
                ),
                "sample",
                "Post_GIF.sample.jpg",
            ),
            (
                "Post_MP4",
                _post(
                    "Post_MP4",
                    file_type="video/mp4",
                    file_ext="mp4",
                    file_size=999,
                    md5="0" * 32,
                    sample_url="",
                ),
                "preview",
                "Post_MP4.preview.jpg",
            ),
        )
        for post_id, post, variant, expected_name in cases:
            with self.subTest(variant=variant):
                response = FakeMediaResponse(
                    200,
                    headers={
                        "Content-Type": "image/jpeg",
                        "Content-Length": str(len(JPEG_COMPLETE)),
                    },
                    chunks=[JPEG_COMPLETE],
                )
                downloader, _api, _session = self._downloader(
                    post, response, prefer_original=False
                )
                result = downloader.download(post_id)

                self.assertEqual(os.path.basename(result.file_path), expected_name)
                self.assertEqual(result.variant, variant)
                self.assertEqual(result.content_type, "image/jpeg")
                self.assertEqual(result.size, len(JPEG_COMPLETE))

    def test_prefer_original_false_prefers_preview_before_original(self):
        response = FakeMediaResponse(
            200,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": str(len(JPEG_COMPLETE)),
            },
            chunks=[JPEG_COMPLETE],
        )
        post = _post(sample_url="")
        downloader, _api, session = self._downloader(
            post, response, prefer_original=False
        )

        result = downloader.download("Post_1")

        self.assertEqual(result.variant, "preview")
        self.assertTrue(result.file_path.endswith("Post_1.preview.jpg"))
        self.assertEqual(session.gets[0]["url"], post.preview_url)

    def test_derivative_rejects_declared_type_or_magic_mismatch(self):
        cases = (
            ("image/png", JPEG, "Content-Type"),
            ("image/jpeg", b"not-media", "签名"),
        )
        for index, (content_type, payload, error) in enumerate(cases):
            with self.subTest(content_type=content_type):
                post_id = f"Post_bad_{index}"
                response = FakeMediaResponse(
                    200,
                    headers={
                        "Content-Type": content_type,
                        "Content-Length": str(len(payload)),
                    },
                    chunks=[payload],
                )
                downloader, _api, _session = self._downloader(
                    _post(post_id), response, prefer_original=False
                )
                with self.assertRaisesRegex(DownloadError, error):
                    downloader.download(post_id)
                self.assertFalse(
                    os.path.exists(
                        os.path.join(self.temp_dir.name, f"{post_id}.sample.jpg")
                    )
                )

    def test_derivative_requires_concrete_response_content_type(self):
        response = FakeMediaResponse(
            200,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": "6",
            },
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(
            _post(), response, prefer_original=False
        )

        with self.assertRaisesRegex(DownloadError, "具体 Content-Type"):
            downloader.download("Post_1")

    def test_derivative_rejects_header_only_jpeg_with_or_without_length(self):
        for include_length in (False, True):
            with self.subTest(include_length=include_length):
                post_id = f"Post_header_{int(include_length)}"
                headers = {"Content-Type": "image/jpeg"}
                if include_length:
                    headers["Content-Length"] = "3"
                response = FakeMediaResponse(
                    200,
                    headers=headers,
                    chunks=[b"\xff\xd8\xff"],
                )
                downloader, _api, _session = self._downloader(
                    _post(post_id), response, prefer_original=False
                )

                with self.assertRaisesRegex(DownloadError, "容器边界"):
                    downloader.download(post_id)
                self.assertFalse(
                    os.path.exists(
                        os.path.join(
                            self.temp_dir.name,
                            f"{post_id}.sample.jpg",
                        )
                    )
                )

    def test_original_extension_metadata_mismatch_is_rejected(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(
            _post(file_ext="png"), response
        )

        with self.assertRaisesRegex(DownloadError, "扩展名"):
            downloader.download("Post_1")

    def test_bare_sample_is_not_reused_and_is_not_overwritten(self):
        bare_path = os.path.join(self.temp_dir.name, "Post_1.sample.jpg")
        with open(bare_path, "wb") as file_obj:
            file_obj.write(JPEG)
        response = FakeMediaResponse(
            200,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": str(len(JPEG_COMPLETE_ALT)),
            },
            chunks=[JPEG_COMPLETE_ALT],
        )
        downloader, _api, session = self._downloader(
            _post(), response, prefer_original=False
        )

        result = downloader.download("Post_1")

        self.assertEqual(len(session.gets), 1)
        self.assertTrue(result.file_path.endswith("Post_1.sample (1).jpg"))
        with open(bare_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG)

    def test_valid_sample_schema2_sidecar_is_reused_after_full_revalidation(self):
        media_path = os.path.join(self.temp_dir.name, "Post_1.sample.jpg")
        with open(media_path, "wb") as file_obj:
            file_obj.write(JPEG_COMPLETE)
        self._write_sidecar(media_path, JPEG_COMPLETE)
        downloader, _api, session = self._downloader(
            _post(), prefer_original=False
        )

        result = downloader.download("Post_1")

        self.assertTrue(result.already_present)
        self.assertEqual(result.variant, "sample")
        self.assertEqual(result.content_type, "image/jpeg")
        self.assertEqual(session.gets, [])

    def test_each_invalid_schema2_sidecar_field_prevents_reuse(self):
        mutations = (
            {"schema_version": 1},
            {"post_id": "Post_other"},
            {"variant": "preview"},
            {"filename": "other.jpg"},
            {"content_type": "image/png"},
            {"extension": "png"},
            {"size": len(JPEG) + 1},
            {"sha256": "0" * 64},
            {"post": {}},
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(field=next(iter(mutation))):
                post_id = f"Post_sidecar_{index}"
                media_path = os.path.join(
                    self.temp_dir.name, f"{post_id}.sample.jpg"
                )
                with open(media_path, "wb") as file_obj:
                    file_obj.write(JPEG)
                self._write_sidecar(
                    media_path,
                    JPEG,
                    post_id=post_id,
                    mutate=mutation,
                )
                response = FakeMediaResponse(
                    200,
                    headers={
                        "Content-Type": "image/jpeg",
                        "Content-Length": str(len(JPEG_COMPLETE_ALT)),
                    },
                    chunks=[JPEG_COMPLETE_ALT],
                )
                downloader, _api, session = self._downloader(
                    _post(post_id), response, prefer_original=False
                )

                result = downloader.download(post_id)

                self.assertEqual(len(session.gets), 1)
                self.assertTrue(
                    result.file_path.endswith(f"{post_id}.sample (1).jpg")
                )
                with open(media_path, "rb") as file_obj:
                    self.assertEqual(file_obj.read(), JPEG)

    def test_original_sidecar_still_requires_fresh_site_size_and_md5(self):
        media_path = os.path.join(self.temp_dir.name, "Post_1.jpg")
        with open(media_path, "wb") as file_obj:
            file_obj.write(JPEG)
        self._write_sidecar(
            media_path,
            JPEG,
            variant="original",
        )
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG_ALT],
        )
        downloader, _api, session = self._downloader(_post(md5=""), response)

        result = downloader.download("Post_1")

        self.assertEqual(len(session.gets), 1)
        self.assertTrue(result.file_path.endswith("Post_1 (1).jpg"))
        with open(media_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG)

    def test_existing_final_or_sidecar_collision_allocates_numbered_slot(self):
        cases = ("final", "sidecar")
        for index, collision_kind in enumerate(cases):
            with self.subTest(collision=collision_kind):
                post_id = f"Post_collision_{index}"
                canonical = os.path.join(self.temp_dir.name, f"{post_id}.jpg")
                collision_path = (
                    canonical if collision_kind == "final" else canonical + ".json"
                )
                preserved = b"unrelated-owner"
                with open(collision_path, "wb") as file_obj:
                    file_obj.write(preserved)
                response = FakeMediaResponse(
                    200,
                    headers={
                        "Content-Type": "image/jpeg",
                        "Content-Length": "6",
                    },
                    chunks=[JPEG],
                )
                downloader, _api, _session = self._downloader(
                    _post(post_id), response
                )

                result = downloader.download(post_id)

                self.assertTrue(result.file_path.endswith(f"{post_id} (1).jpg"))
                with open(collision_path, "rb") as file_obj:
                    self.assertEqual(file_obj.read(), preserved)

    def test_commit_race_never_replaces_winner(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)
        canonical = os.path.join(self.temp_dir.name, "Post_1.jpg")
        real_commit = download_engine._publish_bound_media_name_no_replace
        raced = False

        def race_once(
            root_token: int,
            descriptor: int,
            source: str,
            destination: str,
        ) -> None:
            nonlocal raced
            if destination == "Post_1.jpg" and not raced:
                raced = True
                with open(canonical, "xb") as file_obj:
                    file_obj.write(b"race-winner")
                raise FileExistsError(destination)
            real_commit(root_token, descriptor, source, destination)

        with mock.patch(
            "download_engine._publish_bound_media_name_no_replace",
            side_effect=race_once,
        ):
            result = downloader.download("Post_1")

        self.assertTrue(result.file_path.endswith("Post_1 (1).jpg"))
        with open(canonical, "rb") as file_obj:
            self.assertEqual(file_obj.read(), b"race-winner")

    def test_part_slot_race_uses_new_slot_without_touching_winner(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)
        canonical_part = self._paths()[1]
        real_open_part = download_engine._open_part_for_write
        raced = False

        def race_once(path: str, *, append: bool, expected_size: int):
            nonlocal raced
            if not append and not raced:
                raced = True
                with open(path, "xb") as file_obj:
                    file_obj.write(b"part-race-winner")
                raise download_engine._PartSlotCollision("simulated race")
            return real_open_part(
                path,
                append=append,
                expected_size=expected_size,
            )

        with mock.patch(
            "download_engine._open_part_for_write", side_effect=race_once
        ):
            result = downloader.download("Post_1")

        self.assertTrue(os.path.isfile(result.file_path))
        with open(canonical_part, "rb") as file_obj:
            self.assertEqual(file_obj.read(), b"part-race-winner")

    def test_sidecar_race_is_warning_and_never_overwrites_winner(self):
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(
            _post(), response, save_metadata=True
        )
        real_commit = download_engine._commit_file_no_replace
        winning_sidecar = b'{"owner":"other"}'

        def race_sidecar(source: str, destination: str) -> None:
            if destination.endswith(".jpg.json"):
                with open(destination, "xb") as file_obj:
                    file_obj.write(winning_sidecar)
                raise FileExistsError(destination)
            real_commit(source, destination)

        with mock.patch(
            "download_engine._commit_file_no_replace", side_effect=race_sidecar
        ):
            result = downloader.download("Post_1")

        self.assertIn("未覆盖", result.metadata_warning)
        with open(result.file_path + ".json", "rb") as file_obj:
            self.assertEqual(file_obj.read(), winning_sidecar)

    def test_orphan_part_and_state_are_unchanged_on_success_or_failure(self):
        part_path = self._paths()[1]
        state_path = part_path + ".state.json"
        with open(part_path, "wb") as file_obj:
            file_obj.write(b"unowned-part")
        with open(state_path, "wb") as file_obj:
            file_obj.write(b"not-valid-state")
        with open(part_path, "rb") as file_obj:
            original_part = file_obj.read()
        with open(state_path, "rb") as file_obj:
            original_state = file_obj.read()
        response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "6"},
            chunks=[JPEG],
        )
        downloader, _api, _session = self._downloader(_post(), response)

        result = downloader.download("Post_1")

        self.assertTrue(os.path.isfile(result.file_path))
        with open(part_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), original_part)
        with open(state_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), original_state)

        failed_response = FakeMediaResponse(
            200,
            headers={"Content-Type": "image/jpeg", "Content-Length": "9"},
            chunks=[b"not-media"],
        )
        failed_downloader, _api, _session = self._downloader(
            _post(file_size=9), failed_response
        )
        with self.assertRaises(DownloadError):
            failed_downloader.download("Post_1")
        with open(part_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), original_part)
        with open(state_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), original_state)

    def test_supported_magic_and_mime_table_is_consistent(self):
        cases = (
            (JPEG, "image/jpeg", "jpg"),
            (PNG, "image/png", "png"),
            (GIF, "image/gif", "gif"),
            (WEBP, "image/webp", "webp"),
            (AVIF, "image/avif", "avif"),
            (BMP, "image/bmp", "bmp"),
            (TIFF, "image/tiff", "tiff"),
            (MP4, "video/mp4", "mp4"),
            (MOV, "video/quicktime", "mov"),
            (M4A, "audio/mp4", "m4a"),
            (WEBM, "video/webm", "webm"),
            (MKV, "video/x-matroska", "mkv"),
            (MPEG, "video/mpeg", "mpeg"),
            (AVI, "video/x-msvideo", "avi"),
            (FLV, "video/x-flv", "flv"),
            (ASF, "video/x-ms-wmv", "wmv"),
            (ASF, "audio/x-ms-wma", "wma"),
            (MP3, "audio/mpeg", "mp3"),
            (OGG, "audio/ogg", "ogg"),
            (OPUS, "audio/opus", "opus"),
            (FLAC, "audio/flac", "flac"),
            (WAV, "audio/wav", "wav"),
        )
        for payload, content_type, extension in cases:
            with self.subTest(content_type=content_type):
                inspection = download_engine._FileInspection(
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    md5=hashlib.md5(payload, usedforsecurity=False).hexdigest(),
                    prefix=payload,
                    device=1,
                    inode=1,
                )
                detected = download_engine._resolve_media_format(
                    inspection,
                    declared_type=content_type,
                    expected_type="",
                    expected_extension="",
                    expected_size=0,
                    expected_md5="",
                    require_concrete_declared=True,
                )
                self.assertEqual(detected, (content_type, extension))

    def test_derived_boundary_resolver_covers_all_four_raster_formats(self):
        cases = (
            (JPEG_COMPLETE, "image/jpeg", "jpg"),
            (PNG_COMPLETE, "image/png", "png"),
            (GIF_COMPLETE, "image/gif", "gif"),
            (WEBP_COMPLETE, "image/webp", "webp"),
        )
        for payload, content_type, extension in cases:
            with self.subTest(content_type=content_type):
                inspection = download_engine._FileInspection(
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    md5=hashlib.md5(
                        payload, usedforsecurity=False
                    ).hexdigest(),
                    prefix=payload,
                    device=1,
                    inode=1,
                    suffix=payload[-12:],
                )
                detected = download_engine._resolve_media_format(
                    inspection,
                    declared_type=content_type,
                    expected_type="",
                    expected_extension="",
                    expected_size=0,
                    expected_md5="",
                    require_concrete_declared=True,
                    require_image_boundary=True,
                )
                self.assertEqual(detected, (content_type, extension))

                damaged = payload[:-1]
                damaged_inspection = download_engine._FileInspection(
                    size=len(damaged),
                    sha256=hashlib.sha256(damaged).hexdigest(),
                    md5=hashlib.md5(
                        damaged, usedforsecurity=False
                    ).hexdigest(),
                    prefix=damaged,
                    device=1,
                    inode=1,
                    suffix=damaged[-12:],
                )
                with self.assertRaisesRegex(DownloadError, "容器边界"):
                    download_engine._resolve_media_format(
                        damaged_inspection,
                        declared_type=content_type,
                        expected_type="",
                        expected_extension="",
                        expected_size=0,
                        expected_md5="",
                        require_concrete_declared=True,
                        require_image_boundary=True,
                    )

    def test_ambiguous_containers_require_trusted_type(self):
        for payload in (MP4, ASF, OPUS):
            with self.subTest(payload=payload[:16]):
                inspection = download_engine._FileInspection(
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    md5=hashlib.md5(payload, usedforsecurity=False).hexdigest(),
                    prefix=payload,
                    device=1,
                    inode=1,
                )
                with self.assertRaisesRegex(DownloadError, "歧义"):
                    download_engine._resolve_media_format(
                        inspection,
                        declared_type="application/octet-stream",
                        expected_type="",
                        expected_extension="",
                        expected_size=0,
                        expected_md5="",
                        require_concrete_declared=False,
                    )

    def test_svg_html_json_xml_and_unknown_are_rejected(self):
        payloads = (
            b"<svg xmlns='http://www.w3.org/2000/svg'>",
            b"<html>login</html>",
            b'{"error":true}',
            b"<?xml version='1.0'?><root/>",
            b"unknown-binary",
        )
        for payload in payloads:
            with self.subTest(payload=payload[:8]):
                self.assertEqual(download_engine._media_signatures(payload), frozenset())

    def test_cancellation_keeps_secret_free_resumable_state(self):
        stop_event = threading.Event()

        def cancel_before_second_chunk(index: int) -> None:
            if index == 1:
                stop_event.set()

        response = FakeMediaResponse(
            200,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": "6",
                "ETag": '"v1"',
            },
            chunks=[JPEG[:3], JPEG[3:]],
            before_chunk=cancel_before_second_chunk,
        )
        secret_url = (
            "https://cs.sankakucomplex.com/data/file.jpg"
            "?e=1700000000&m=MEDIA_URL_SECRET"
        )
        downloader, _api, _session = self._downloader(
            _post(file_url=secret_url), response, stop_event=stop_event
        )

        with self.assertRaises(CancelledError):
            downloader.download("Post_1")

        final_path, part_path, state_path = self._paths()
        self.assertFalse(os.path.exists(final_path))
        self.assertTrue(os.path.isfile(part_path))
        with open(part_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), JPEG[:3])
        with open(state_path, "r", encoding="ascii") as file_obj:
            raw_state = file_obj.read()
        state = json.loads(raw_state)
        self.assertEqual(
            set(state),
            {
                "schema_version",
                "post_id",
                "variant",
                "declared_type",
                "expected_size",
                "expected_md5",
                "etag",
                "last_modified",
                "total_size",
            },
        )
        self.assertNotIn("https://", raw_state)
        self.assertNotIn("MEDIA_URL_SECRET", raw_state)
        self.assertNotIn("token", raw_state.lower())
        self.assertTrue(response.closed)


class LocalDownloadVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

    def _write_pair(
        self,
        *,
        filename: str = "Post_local.jpg",
        media: bytes = JPEG,
        sidecar_media: bytes | None = None,
        post_id: str = "Post_local",
        variant: str = "original",
        content_type: str = "image/jpeg",
        extension: str = "jpg",
        mutate: dict[str, object] | None = None,
    ) -> tuple[str, str]:
        media_path = os.path.join(self.temp_dir.name, filename)
        with open(media_path, "wb") as file_obj:
            file_obj.write(media)
        described = media if sidecar_media is None else sidecar_media
        payload = {
            "schema_version": 2,
            "post_id": post_id,
            "variant": variant,
            "filename": filename,
            "content_type": content_type,
            "extension": extension,
            "size": len(described),
            "sha256": hashlib.sha256(described).hexdigest(),
            "post": {
                "rating": "s",
                "status": "active",
                "width": 1200,
                "height": 800,
                "tags": ["cat", "blue_eyes"],
                "author": "artist",
                "created_at": "1700000000",
                "is_premium": False,
            },
        }
        if mutate:
            payload.update(mutate)
        metadata_path = media_path + ".json"
        with open(metadata_path, "w", encoding="utf-8") as file_obj:
            json.dump(payload, file_obj)
        return media_path, metadata_path

    def test_valid_pair_is_fully_verified_without_mutation(self):
        media_path, metadata_path = self._write_pair()
        with open(media_path, "rb") as file_obj:
            media_before = file_obj.read()
        with open(metadata_path, "rb") as file_obj:
            metadata_before = file_obj.read()

        result = verify_local_download(
            media_path,
            output_dir=self.temp_dir.name,
        )

        self.assertEqual(result.post_id, "Post_local")
        self.assertEqual(result.variant, "original")
        self.assertEqual(result.relative_path, "Post_local.jpg")
        self.assertEqual(result.size, len(JPEG))
        self.assertEqual(result.sha256, hashlib.sha256(JPEG).hexdigest())
        self.assertEqual(result.content_type, "image/jpeg")
        self.assertEqual(result.extension, "jpg")
        self.assertEqual(result.tags, ("cat", "blue_eyes"))
        with open(media_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), media_before)
        with open(metadata_path, "rb") as file_obj:
            self.assertEqual(file_obj.read(), metadata_before)

    def test_bound_verifier_matches_the_legacy_verified_result(self):
        media_path, _metadata_path = self._write_pair()
        legacy = verify_local_download(
            media_path,
            output_dir=self.temp_dir.name,
        )

        with open_bound_root(self.temp_dir.name) as session:
            bound = verify_bound_local_download(session, "Post_local.jpg")

        self.assertEqual(bound, legacy)

    def test_complete_sample_passes_plain_and_bound_revalidation(self):
        media_path, _metadata_path = self._write_pair(
            filename="Post_local.sample.jpg",
            media=JPEG_COMPLETE,
            variant="sample",
        )
        legacy = verify_local_download(
            media_path,
            output_dir=self.temp_dir.name,
        )

        with open_bound_root(self.temp_dir.name) as session:
            bound = verify_bound_local_download(
                session, "Post_local.sample.jpg"
            )

        self.assertEqual(legacy.variant, "sample")
        self.assertEqual(legacy, bound)

    def test_header_only_sample_fails_plain_and_bound_revalidation(self):
        media_path, _metadata_path = self._write_pair(
            filename="Post_local.sample.jpg",
            media=b"\xff\xd8\xff",
            variant="sample",
        )

        with self.assertRaisesRegex(
            LocalIntegrityError, "容器边界"
        ) as plain:
            verify_local_download(
                media_path,
                output_dir=self.temp_dir.name,
            )
        self.assertEqual(plain.exception.checked_bytes, 3)

        with open_bound_root(self.temp_dir.name) as session:
            with self.assertRaisesRegex(
                LocalIntegrityError, "容器边界"
            ) as bound:
                verify_bound_local_download(
                    session, "Post_local.sample.jpg"
                )
        self.assertEqual(bound.exception.checked_bytes, 3)

    def test_bound_missing_or_invalid_sidecar_never_hashes_media(self):
        media_path = os.path.join(self.temp_dir.name, "Post_local.jpg")
        with open(media_path, "wb") as file_obj:
            file_obj.write(JPEG)
        with open_bound_root(self.temp_dir.name) as session, mock.patch.object(
            BoundRootSession, "inspect_child", autospec=True
        ) as inspect:
            with self.assertRaises(LocalMetadataError) as raised:
                verify_bound_local_download(session, "Post_local.jpg")
            self.assertEqual(raised.exception.status, "missing_metadata")
            inspect.assert_not_called()

        with open(media_path + ".json", "wb") as file_obj:
            file_obj.write(b"not-json")
        with open_bound_root(self.temp_dir.name) as session, mock.patch.object(
            BoundRootSession, "inspect_child", autospec=True
        ) as inspect:
            with self.assertRaises(LocalMetadataError) as raised:
                verify_bound_local_download(session, "Post_local.jpg")
            self.assertEqual(raised.exception.status, "invalid_metadata")
            inspect.assert_not_called()

    def test_bound_orphan_and_tampered_media_keep_status_and_checked_bytes(self):
        media_path, _metadata_path = self._write_pair()
        os.remove(media_path)
        with open_bound_root(self.temp_dir.name) as session:
            with self.assertRaises(LocalIntegrityError) as raised:
                verify_bound_local_download(session, "Post_local.jpg")
        self.assertEqual(raised.exception.status, "missing_media")

        self._write_pair(media=JPEG_ALT, sidecar_media=JPEG)
        with open_bound_root(self.temp_dir.name) as session:
            with self.assertRaises(LocalIntegrityError) as raised:
                verify_bound_local_download(session, "Post_local.jpg")
        self.assertEqual(raised.exception.status, "changed")
        self.assertEqual(raised.exception.checked_bytes, len(JPEG_ALT))

    def test_bound_sidecar_change_during_media_hash_is_not_verified(self):
        _media_path, metadata_path = self._write_pair()
        with open_bound_root(self.temp_dir.name) as session:
            real_inspect = session.inspect_child

            def inspect_then_edit(_session, *args, **kwargs):
                result = real_inspect(*args, **kwargs)
                with open(metadata_path, "ab") as file_obj:
                    file_obj.write(b" ")
                return result

            with mock.patch.object(
                BoundRootSession,
                "inspect_child",
                autospec=True,
                side_effect=inspect_then_edit,
            ):
                with self.assertRaises(LocalIntegrityError) as raised:
                    verify_bound_local_download(session, "Post_local.jpg")

        self.assertEqual(raised.exception.status, "changed")
        self.assertEqual(raised.exception.checked_bytes, len(JPEG))

    def test_bound_unreadable_media_stat_is_preserved(self):
        self._write_pair()
        secret = os.path.join(self.temp_dir.name, "private-stat-detail")

        with open_bound_root(self.temp_dir.name) as session, mock.patch.object(
            BoundRootSession,
            "stat_child",
            autospec=True,
            side_effect=BoundFileUnreadable(secret),
        ):
            with self.assertRaises(LocalIntegrityError) as raised:
                verify_bound_local_download(session, "Post_local.jpg")

        self.assertEqual(raised.exception.status, "unreadable")
        self.assertEqual(raised.exception.checked_bytes, 0)
        self.assertEqual(str(raised.exception), "本地媒体不可读")
        self.assertNotIn(secret, str(raised.exception))

    def test_bound_unreadable_initial_sidecar_does_not_hash_media(self):
        self._write_pair()
        secret = os.path.join(self.temp_dir.name, "private-sidecar-detail")

        with open_bound_root(self.temp_dir.name) as session, mock.patch.object(
            BoundRootSession,
            "read_small_file",
            autospec=True,
            side_effect=BoundFileUnreadable(secret),
        ), mock.patch.object(
            BoundRootSession, "inspect_child", autospec=True
        ) as inspect:
            with self.assertRaises(LocalMetadataError) as raised:
                verify_bound_local_download(session, "Post_local.jpg")

        self.assertEqual(raised.exception.status, "unreadable")
        self.assertEqual(str(raised.exception), "本地元数据不可读")
        self.assertNotIn(secret, str(raised.exception))
        inspect.assert_not_called()

    def test_bound_unreadable_media_read_never_commits_verification(self):
        self._write_pair()
        secret = os.path.join(self.temp_dir.name, "private-media-detail")

        with open_bound_root(self.temp_dir.name) as session, mock.patch.object(
            BoundRootSession,
            "inspect_child",
            autospec=True,
            side_effect=BoundFileUnreadable(secret),
        ):
            with self.assertRaises(LocalIntegrityError) as raised:
                verify_bound_local_download(session, "Post_local.jpg")

        self.assertEqual(raised.exception.status, "unreadable")
        self.assertEqual(raised.exception.checked_bytes, 0)
        self.assertEqual(str(raised.exception), "本地媒体不可读")
        self.assertNotIn(secret, str(raised.exception))

    def test_bound_unreadable_refreshed_sidecar_preserves_checked_bytes(self):
        self._write_pair()
        secret = os.path.join(self.temp_dir.name, "private-refresh-detail")

        with open_bound_root(self.temp_dir.name) as session:
            real_read = session.read_small_file
            call_count = 0

            def fail_second_read(_session, *args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 2:
                    raise BoundFileUnreadable(secret)
                return real_read(*args, **kwargs)

            with mock.patch.object(
                BoundRootSession,
                "read_small_file",
                autospec=True,
                side_effect=fail_second_read,
            ):
                with self.assertRaises(LocalIntegrityError) as raised:
                    verify_bound_local_download(session, "Post_local.jpg")

        self.assertEqual(call_count, 2)
        self.assertEqual(raised.exception.status, "unreadable")
        self.assertEqual(raised.exception.checked_bytes, len(JPEG))
        self.assertEqual(str(raised.exception), "本地元数据不可读")
        self.assertNotIn(secret, str(raised.exception))

    def test_bound_pre_cancelled_verification_uses_shared_cancelled_error(self):
        self._write_pair()
        stopped = threading.Event()
        stopped.set()
        with open_bound_root(self.temp_dir.name) as session:
            with self.assertRaises(CancelledError):
                verify_bound_local_download(
                    session,
                    "Post_local.jpg",
                    stop_event=stopped,
                )

    def test_missing_or_invalid_sidecar_is_classified_before_hashing(self):
        media_path = os.path.join(self.temp_dir.name, "Post_local.jpg")
        with open(media_path, "wb") as file_obj:
            file_obj.write(JPEG)
        with mock.patch("download_engine._inspect_media_file") as inspect:
            with self.assertRaises(LocalMetadataError) as raised:
                verify_local_download(media_path, output_dir=self.temp_dir.name)
            self.assertEqual(raised.exception.status, "missing_metadata")
            inspect.assert_not_called()

        metadata_path = media_path + ".json"
        with open(metadata_path, "wb") as file_obj:
            file_obj.write(b"not-json")
        with mock.patch("download_engine._inspect_media_file") as inspect:
            with self.assertRaises(LocalMetadataError) as raised:
                verify_local_download(media_path, output_dir=self.temp_dir.name)
            self.assertEqual(raised.exception.status, "invalid_metadata")
            inspect.assert_not_called()

    def test_missing_media_is_classified_from_orphan_sidecar(self):
        media_path, _metadata_path = self._write_pair()
        os.remove(media_path)

        with self.assertRaises(LocalIntegrityError) as raised:
            verify_local_download(media_path, output_dir=self.temp_dir.name)

        self.assertEqual(raised.exception.status, "missing_media")

    def test_tampered_media_is_changed_with_checked_byte_count(self):
        media_path, _metadata_path = self._write_pair(
            media=JPEG_ALT,
            sidecar_media=JPEG,
        )

        with self.assertRaises(LocalIntegrityError) as raised:
            verify_local_download(media_path, output_dir=self.temp_dir.name)

        self.assertEqual(raised.exception.status, "changed")
        self.assertEqual(raised.exception.checked_bytes, len(JPEG_ALT))
        self.assertIn("SHA-256", str(raised.exception))

    def test_hash_matching_non_media_signature_is_changed(self):
        media_path, _metadata_path = self._write_pair(media=b"not-media")

        with self.assertRaisesRegex(LocalIntegrityError, "签名") as raised:
            verify_local_download(media_path, output_dir=self.temp_dir.name)

        self.assertEqual(raised.exception.status, "changed")
        self.assertEqual(raised.exception.checked_bytes, len(b"not-media"))

    def test_metadata_filename_mismatch_is_rejected_before_hashing(self):
        media_path, _metadata_path = self._write_pair(
            mutate={"filename": "Other.jpg"}
        )

        with mock.patch("download_engine._inspect_media_file") as inspect:
            with self.assertRaisesRegex(LocalMetadataError, "文件名") as raised:
                verify_local_download(media_path, output_dir=self.temp_dir.name)
            self.assertEqual(raised.exception.status, "invalid_metadata")
            inspect.assert_not_called()

    def test_nested_media_is_unsafe_before_file_access(self):
        nested = os.path.join(self.temp_dir.name, "nested")
        os.mkdir(nested)
        media_path = os.path.join(nested, "Post_local.jpg")

        with mock.patch("download_engine._plain_file_stat") as plain_stat:
            with self.assertRaisesRegex(LocalIntegrityError, "第一层") as raised:
                verify_local_download(media_path, output_dir=self.temp_dir.name)
            self.assertEqual(raised.exception.status, "unsafe_path")
            plain_stat.assert_not_called()

    def test_plain_file_access_failure_is_unreadable(self):
        media_path, _metadata_path = self._write_pair()
        real_open = download_engine.os.open

        def deny_media(path: str, flags: int, *args):
            if os.path.normcase(path) == os.path.normcase(media_path):
                raise PermissionError("denied")
            return real_open(path, flags, *args)

        with mock.patch("download_engine.os.open", side_effect=deny_media):
            with self.assertRaises(LocalIntegrityError) as raised:
                verify_local_download(media_path, output_dir=self.temp_dir.name)

        self.assertEqual(raised.exception.status, "unreadable")

    def test_sidecar_reparse_point_is_unsafe_even_before_parsing(self):
        media_path, metadata_path = self._write_pair()
        real_lstat = download_engine.os.lstat
        metadata_stat = real_lstat(metadata_path)
        unsafe = SimpleNamespace(
            st_mode=metadata_stat.st_mode,
            st_size=metadata_stat.st_size,
            st_dev=metadata_stat.st_dev,
            st_ino=metadata_stat.st_ino,
            st_file_attributes=getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
        )

        def selective_lstat(path: str):
            if os.path.normcase(path) == os.path.normcase(metadata_path):
                return unsafe
            return real_lstat(path)

        with mock.patch("download_engine.os.lstat", side_effect=selective_lstat):
            with self.assertRaises(LocalMetadataError) as raised:
                verify_local_download(media_path, output_dir=self.temp_dir.name)

        self.assertEqual(raised.exception.status, "unsafe_path")

    def test_sidecar_content_change_during_media_hash_is_not_verified(self):
        media_path, metadata_path = self._write_pair()
        real_inspect = download_engine._inspect_media_file

        def inspect_then_edit(path, stop_event):
            inspection = real_inspect(path, stop_event)
            with open(metadata_path, "r", encoding="utf-8") as file_obj:
                document = json.load(file_obj)
            document["post"]["author"] = "changed-during-scan"
            with open(metadata_path, "w", encoding="utf-8") as file_obj:
                json.dump(document, file_obj)
            return inspection

        with mock.patch(
            "download_engine._inspect_media_file", side_effect=inspect_then_edit
        ):
            with self.assertRaises(LocalIntegrityError) as raised:
                verify_local_download(media_path, output_dir=self.temp_dir.name)

        self.assertEqual(raised.exception.status, "changed")
        self.assertEqual(raised.exception.checked_bytes, len(JPEG))

    def test_sidecar_path_replacement_during_media_hash_is_unsafe(self):
        media_path, metadata_path = self._write_pair()
        with open(metadata_path, "rb") as file_obj:
            original = file_obj.read()
        real_inspect = download_engine._inspect_media_file

        def inspect_then_replace(path, stop_event):
            inspection = real_inspect(path, stop_event)
            replacement = metadata_path + ".replacement"
            with open(replacement, "wb") as file_obj:
                file_obj.write(original)
            os.replace(replacement, metadata_path)
            return inspection

        with mock.patch(
            "download_engine._inspect_media_file", side_effect=inspect_then_replace
        ):
            with self.assertRaises(LocalIntegrityError) as raised:
                verify_local_download(media_path, output_dir=self.temp_dir.name)

        self.assertEqual(raised.exception.status, "unsafe_path")
        self.assertEqual(raised.exception.checked_bytes, len(JPEG))

    def test_public_local_verification_api_is_exported(self):
        self.assertTrue(
            {
                "LOCAL_MEDIA_EXTENSIONS",
                "LocalIntegrityError",
                "LocalMediaVerification",
                "LocalMetadataError",
                "verify_bound_local_download",
                "verify_local_download",
            }.issubset(download_engine.__all__)
        )

    def test_pre_cancelled_verification_uses_shared_cancelled_error(self):
        stop_event = threading.Event()
        stop_event.set()

        with self.assertRaises(CancelledError):
            verify_local_download(
                os.path.join(self.temp_dir.name, "Post_local.jpg"),
                output_dir=self.temp_dir.name,
                stop_event=stop_event,
            )


if __name__ == "__main__":
    unittest.main()
