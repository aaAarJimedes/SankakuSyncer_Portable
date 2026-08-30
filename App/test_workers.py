# -*- coding: utf-8 -*-
"""Offline tests for thumbnail worker pacing and cancellation."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import os
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import workers
from bound_file_reader import BoundRootIdentity
from credential_vault import Credentials
from library_thumbnail import VerifiedThumbnailSource
from download_engine import MediaAccessDeniedError
from sankaku_api import AccessDeniedError, AuthenticationError, RateLimitError
from workers import (
    DownloadWorker,
    LibraryScanWorker,
    LibraryThumbnailWorker,
    LoginWorker,
    SearchWorker,
    ThumbnailWorker,
    _thumbnail_payload_allowed,
)


JPEG_THUMBNAIL = base64.b64decode(
    b"/9j/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"
    b"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/xAAmAAEAAAAAAAAAAAAAAAAA"
    b"AAAAEAEAAAAAAAAAAAAAAAAAAAAA/8AACwgAAQABAQERAP/aAAgBAQAAPwA//9k="
)
PNG_THUMBNAIL = base64.b64decode(
    b"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABAQAAAAA3bvkkAAAACklEQVR42mNg"
    b"AAAAAgAB5Sfe/AAAAABJRU5ErkJggg=="
)
GIF_THUMBNAIL = base64.b64decode(
    b"R0lGODdhAQABAIEAAAECAwAAAAAAAAAAACwAAAAAAQABAAAIBAABBAQAOw=="
)
WEBP_THUMBNAIL = base64.b64decode(
    b"UklGRiAAAABXRUJQVlA4TBQAAAAvAAAAAAdQgVQIIAAKmv7HiIj+Bw=="
)


class FakeResponse:
    def __init__(self, status_code: int, *, headers=None, chunks=None, before_chunk=None):
        self.status_code = status_code
        self.headers = dict(headers or {})
        self.chunks = list(chunks or [])
        self.before_chunk = before_chunk
        self.closed = False

    def iter_content(self, _chunk_size: int):
        for index, chunk in enumerate(self.chunks):
            if self.before_chunk is not None:
                self.before_chunk(index)
            yield chunk

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, responses: list[FakeResponse]):
        self.responses = list(responses)
        self.trust_env = True
        self.gets: list[tuple[str, dict[str, object]]] = []
        self.closed = False

    def get(self, url: str, **kwargs) -> FakeResponse:
        self.gets.append((url, kwargs))
        if not self.responses:
            raise AssertionError("fake session exhausted; network is forbidden")
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True


class RecordingGate:
    def __init__(self):
        self.min_intervals: list[float] = []
        self.deferred: list[float] = []

    @contextmanager
    def slot(self, _stop_event: threading.Event, *, min_interval: float = 0.0):
        self.min_intervals.append(min_interval)
        yield

    def defer(self, seconds: float) -> None:
        self.deferred.append(seconds)


class ThumbnailWorkerOfflineTests(unittest.TestCase):
    def _run(self, response: FakeResponse, *, before_run=None):
        session = FakeSession([response])
        gate = RecordingGate()
        worker = ThumbnailWorker(7, "123", "https://s.sankakucomplex.com/a.jpg")
        succeeded: list[tuple] = []
        failed: list[tuple] = []
        worker.signals.succeeded.connect(lambda *args: succeeded.append(args))
        worker.signals.failed.connect(lambda *args: failed.append(args))
        if before_run is not None:
            before_run(worker)
        with (
            mock.patch("workers.Session", return_value=session),
            mock.patch("workers.MEDIA_REQUEST_GATE", gate),
        ):
            worker.run()
        return worker, session, gate, succeeded, failed

    def test_success_uses_identity_encoding_shared_pacing_and_no_ambient_proxy(self):
        response = FakeResponse(
            200,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": str(len(JPEG_THUMBNAIL)),
            },
            chunks=[JPEG_THUMBNAIL[:80], JPEG_THUMBNAIL[80:]],
        )
        worker, session, gate, succeeded, failed = self._run(response)
        self.assertEqual(succeeded, [(7, "123", JPEG_THUMBNAIL)])
        self.assertEqual(failed, [])
        self.assertEqual(gate.min_intervals, [0.5])
        self.assertFalse(session.trust_env)
        self.assertEqual(session.gets[0][1]["headers"]["Accept-Encoding"], "identity")
        self.assertFalse(session.gets[0][1]["allow_redirects"])
        self.assertTrue(response.closed)

    def test_valid_thumbnail_without_content_length_remains_supported(self):
        response = FakeResponse(
            200,
            headers={"Content-Type": "image/jpeg"},
            chunks=[JPEG_THUMBNAIL],
        )

        _worker, session, _gate, succeeded, failed = self._run(response)

        self.assertEqual(succeeded, [(7, "123", JPEG_THUMBNAIL)])
        self.assertEqual(failed, [])
        self.assertTrue(response.closed)
        self.assertTrue(session.closed)

    def test_thumbnail_content_length_must_be_strict_and_match_the_body(self):
        invalid_or_mismatched = (
            "",
            "-1",
            "+1",
            " 1",
            "\N{FULLWIDTH DIGIT ONE}",
            "\N{SUPERSCRIPT TWO}",
            "9" * 5000,
            str(len(JPEG_THUMBNAIL) - 1),
            str(len(JPEG_THUMBNAIL) + 1),
        )
        for declared in invalid_or_mismatched:
            with self.subTest(declared=declared[:20]):
                response = FakeResponse(
                    200,
                    headers={
                        "Content-Type": "image/jpeg",
                        "Content-Length": declared,
                    },
                    chunks=[JPEG_THUMBNAIL],
                )

                _worker, session, _gate, succeeded, failed = self._run(response)

                self.assertEqual(succeeded, [])
                self.assertEqual(failed, [(7, "123")])
                self.assertTrue(response.closed)
                self.assertTrue(session.closed)

    def test_declared_oversize_thumbnail_is_rejected_before_streaming(self):
        before_chunk = mock.Mock(side_effect=AssertionError("body must not be read"))
        response = FakeResponse(
            200,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Length": str(ThumbnailWorker.MAX_BYTES + 1),
            },
            chunks=[JPEG_THUMBNAIL],
            before_chunk=before_chunk,
        )

        _worker, session, _gate, succeeded, failed = self._run(response)

        self.assertEqual(succeeded, [])
        self.assertEqual(failed, [(7, "123")])
        before_chunk.assert_not_called()
        self.assertTrue(response.closed)
        self.assertTrue(session.closed)

    def test_cancel_closes_live_session_and_unblocks_request(self):
        class BlockingSession:
            def __init__(self):
                self.trust_env = True
                self.entered = threading.Event()
                self.closed = threading.Event()
                self.close_count = 0

            def get(self, _url: str, **_kwargs):
                self.entered.set()
                if not self.closed.wait(3):
                    raise AssertionError("thumbnail Session.close was not called")
                raise RuntimeError("offline fake cancelled")

            def close(self):
                self.close_count += 1
                self.closed.set()

        session = BlockingSession()
        gate = RecordingGate()
        worker = ThumbnailWorker(8, "456", "https://s.sankakucomplex.com/a.jpg")
        failed: list[tuple] = []
        worker.signals.failed.connect(lambda *args: failed.append(args))
        with (
            mock.patch("workers.Session", return_value=session),
            mock.patch("workers.MEDIA_REQUEST_GATE", gate),
        ):
            thread = threading.Thread(target=worker.run, daemon=True)
            thread.start()
            self.assertTrue(session.entered.wait(1))
            worker.cancel()
            thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(session.close_count, 1)
        self.assertEqual(worker.url, "")
        self.assertTrue(session.closed)
        self.assertEqual(worker.url, "")

    def test_svg_and_disguised_non_images_are_rejected(self):
        for content_type, payload in (
            ("image/svg+xml", b"<svg xmlns='http://www.w3.org/2000/svg'/>"),
            ("image/jpeg", b"<html>not an image</html>"),
            ("image/png", b"<?xml version='1.0'?><svg/>"),
        ):
            with self.subTest(content_type=content_type):
                response = FakeResponse(
                    200,
                    headers={"Content-Type": content_type},
                    chunks=[payload],
                )
                _worker, _session, _gate, succeeded, failed = self._run(response)
                self.assertEqual(succeeded, [])
                self.assertEqual(failed, [(7, "123")])
                self.assertTrue(response.closed)

    def test_compressed_thumbnail_is_rejected_before_streaming(self):
        response = FakeResponse(
            200,
            headers={
                "Content-Type": "image/jpeg",
                "Content-Encoding": "gzip",
            },
            chunks=[b"\xff\xd8\xffmust-not-be-used"],
        )
        _worker, session, _gate, succeeded, failed = self._run(response)
        self.assertEqual(succeeded, [])
        self.assertEqual(failed, [(7, "123")])
        self.assertEqual(
            session.gets[0][1]["headers"]["Accept-Encoding"], "identity"
        )
        self.assertTrue(response.closed)

    def test_supported_raster_signatures_match_the_declared_type(self):
        accepted = (
            ("image/jpeg; charset=binary", JPEG_THUMBNAIL),
            ("image/png", PNG_THUMBNAIL),
            ("image/gif", GIF_THUMBNAIL),
            ("image/webp", WEBP_THUMBNAIL),
        )
        for content_type, payload in accepted:
            with self.subTest(content_type=content_type):
                self.assertTrue(_thumbnail_payload_allowed(content_type, payload))
        self.assertFalse(
            _thumbnail_payload_allowed("image/png", b"\xff\xd8\xffnot-png")
        )

    def test_truncated_appended_and_bad_length_rasters_are_rejected(self):
        bad_webp = bytearray(WEBP_THUMBNAIL)
        bad_webp[4:8] = (len(WEBP_THUMBNAIL) - 9).to_bytes(4, "little")
        rejected = (
            ("image/jpeg", b"\xff\xd8\xff"),
            ("image/jpeg", JPEG_THUMBNAIL[:-2]),
            ("image/jpeg", JPEG_THUMBNAIL + b"x"),
            ("image/png", PNG_THUMBNAIL[:-12]),
            ("image/png", PNG_THUMBNAIL + b"x"),
            ("image/gif", GIF_THUMBNAIL[:-1]),
            ("image/gif", GIF_THUMBNAIL + b"x"),
            ("image/webp", WEBP_THUMBNAIL[:-1]),
            ("image/webp", WEBP_THUMBNAIL + b"x"),
            ("image/webp", bytes(bad_webp)),
        )
        for content_type, payload in rejected:
            with self.subTest(content_type=content_type, size=len(payload)):
                self.assertFalse(
                    _thumbnail_payload_allowed(content_type, payload)
                )

    def test_header_only_jpeg_never_emits_thumbnail_success(self):
        for headers in (
            {"Content-Type": "image/jpeg", "Content-Length": "3"},
            {"Content-Type": "image/jpeg"},
        ):
            with self.subTest(headers=headers):
                response = FakeResponse(
                    200,
                    headers=headers,
                    chunks=[b"\xff\xd8\xff"],
                )
                _worker, _session, _gate, succeeded, failed = self._run(response)
                self.assertEqual(succeeded, [])
                self.assertEqual(failed, [(7, "123")])
                self.assertTrue(response.closed)

    def test_rate_limit_defers_the_process_gate_and_fails_closed(self):
        response = FakeResponse(429, headers={"Retry-After": "30"})
        _worker, _session, gate, succeeded, failed = self._run(response)
        self.assertEqual(gate.deferred, [30.0])
        self.assertEqual(succeeded, [])
        self.assertEqual(failed, [(7, "123")])
        self.assertTrue(response.closed)

    def test_non_finite_rate_limit_uses_default_process_cooldown(self):
        response = FakeResponse(429, headers={"Retry-After": "NaN"})
        _worker, _session, gate, succeeded, failed = self._run(response)
        self.assertEqual(gate.deferred, [600.0])
        self.assertEqual(succeeded, [])
        self.assertEqual(failed, [(7, "123")])
        self.assertTrue(response.closed)

    def test_pre_cancelled_worker_never_starts_an_http_request(self):
        response = FakeResponse(
            200,
            headers={"Content-Type": "image/jpeg"},
            chunks=[b"must-not-be-read"],
        )
        worker, session, _gate, succeeded, failed = self._run(
            response, before_run=lambda candidate: candidate.cancel()
        )
        self.assertEqual(session.gets, [])
        self.assertEqual(succeeded, [])
        self.assertEqual(failed, [(7, "123")])
        self.assertEqual(worker.url, "")

    def test_cancellation_during_stream_never_emits_partial_image(self):
        holder: dict[str, ThumbnailWorker] = {}

        def cancel_on_first_chunk(_index: int) -> None:
            holder["worker"].cancel()

        response = FakeResponse(
            200,
            headers={"Content-Type": "image/jpeg"},
            chunks=[b"partial"],
            before_chunk=cancel_on_first_chunk,
        )

        def remember(worker: ThumbnailWorker) -> None:
            holder["worker"] = worker

        _worker, _session, _gate, succeeded, failed = self._run(
            response, before_run=remember
        )
        self.assertEqual(succeeded, [])
        self.assertEqual(failed, [(7, "123")])
        self.assertTrue(response.closed)


class LibraryScanWorkerOfflineTests(unittest.TestCase):
    def test_success_forwards_progress_and_one_complete_report(self):
        report = SimpleNamespace(entries=("entry",), checked_bytes=5_000_000_000)

        def scan(_output_dir, *, stop_event, progress):
            self.assertFalse(stop_event.is_set())
            progress(2, 7, 5_000_000_000)
            return report

        worker = LibraryScanWorker("relative-library")
        progress_values: list[tuple] = []
        succeeded: list[object] = []
        failed: list[str] = []
        cancelled: list[bool] = []
        worker.progress.connect(lambda *args: progress_values.append(args))
        worker.succeeded.connect(succeeded.append)
        worker.failed.connect(failed.append)
        worker.cancelled.connect(lambda: cancelled.append(True))
        with mock.patch("workers.scan_download_library", side_effect=scan):
            worker.run()
        self.assertEqual(progress_values, [(2, 7, 5_000_000_000)])
        self.assertEqual(succeeded, [report])
        self.assertEqual(failed, [])
        self.assertEqual(cancelled, [])

    def test_pre_cancel_and_cancel_after_scanner_return_never_emit_success(self):
        pre_cancelled = LibraryScanWorker("library")
        pre_cancelled.cancel()
        pre_events: list[bool] = []
        pre_cancelled.cancelled.connect(lambda: pre_events.append(True))
        with mock.patch("workers.scan_download_library") as scan:
            pre_cancelled.run()
        scan.assert_not_called()
        self.assertEqual(pre_events, [True])

        late = LibraryScanWorker("library")
        succeeded: list[object] = []
        cancelled: list[bool] = []
        late.succeeded.connect(succeeded.append)
        late.cancelled.connect(lambda: cancelled.append(True))

        def cancel_then_return(*_args, **_kwargs):
            late.cancel()
            return SimpleNamespace(entries=())

        with mock.patch(
            "workers.scan_download_library", side_effect=cancel_then_return
        ):
            late.run()
        self.assertEqual(succeeded, [])
        self.assertEqual(cancelled, [True])

    def test_known_and_unknown_failures_are_safely_reported(self):
        known = LibraryScanWorker("library")
        known_errors: list[str] = []
        known.failed.connect(known_errors.append)
        with mock.patch(
            "workers.scan_download_library",
            side_effect=workers.LibraryScanError("目录候选项超过安全上限"),
        ):
            known.run()
        self.assertEqual(known_errors, ["目录候选项超过安全上限"])

        unknown = LibraryScanWorker("library")
        unknown_errors: list[str] = []
        unknown.failed.connect(unknown_errors.append)
        with mock.patch(
            "workers.scan_download_library",
            side_effect=RuntimeError("sensitive raw path"),
        ):
            unknown.run()
        self.assertEqual(len(unknown_errors), 1)
        self.assertIn("RuntimeError", unknown_errors[0])
        self.assertNotIn("sensitive raw path", unknown_errors[0])


class LibraryThumbnailWorkerOfflineTests(unittest.TestCase):
    @staticmethod
    def _source(name: str) -> VerifiedThumbnailSource:
        content_type = "image/png" if name.casefold().endswith(".png") else "image/jpeg"
        identity = BoundRootIdentity(
            "windows" if os.name == "nt" else "posix", 1, b"root"
        )
        return VerifiedThumbnailSource(
            name, 123, "a" * 64, content_type, identity
        )

    @staticmethod
    def _events(worker: LibraryThumbnailWorker):
        succeeded: list[object] = []
        failed: list[str] = []
        cancelled: list[bool] = []
        worker.succeeded.connect(succeeded.append)
        worker.failed.connect(failed.append)
        worker.cancelled.connect(lambda: cancelled.append(True))
        return succeeded, failed, cancelled

    def test_success_forwards_paths_stop_event_and_result(self):
        result = SimpleNamespace(relative_path="Post_A.jpg", png_bytes=b"png")
        source = self._source("Post_A.jpg")
        worker = LibraryThumbnailWorker("relative-library", source)
        succeeded, failed, cancelled = self._events(worker)

        def load(output_dir, actual_source, stop_event=None):
            self.assertEqual(output_dir, os.path.abspath("relative-library"))
            self.assertIs(actual_source, source)
            self.assertIs(stop_event, worker.stop_event)
            self.assertFalse(stop_event.is_set())
            return result

        with mock.patch("workers.load_library_thumbnail", side_effect=load) as loader:
            worker.run()

        loader.assert_called_once()
        self.assertEqual(succeeded, [result])
        self.assertEqual(failed, [])
        self.assertEqual(cancelled, [])

    def test_pre_and_late_cancel_emit_only_cancelled(self):
        pre = LibraryThumbnailWorker("library", self._source("Post_A.jpg"))
        pre_succeeded, pre_failed, pre_cancelled = self._events(pre)
        pre.cancel()
        pre.cancel()
        with mock.patch("workers.load_library_thumbnail") as loader:
            pre.run()
        loader.assert_not_called()
        self.assertEqual(pre_succeeded, [])
        self.assertEqual(pre_failed, [])
        self.assertEqual(pre_cancelled, [True])

        late = LibraryThumbnailWorker("library", self._source("Post_B.png"))
        late_succeeded, late_failed, late_cancelled = self._events(late)
        result = SimpleNamespace(relative_path="Post_B.png", png_bytes=b"png")

        def cancel_then_return(*_args, **_kwargs):
            late.cancel()
            late.cancel()
            return result

        with mock.patch(
            "workers.load_library_thumbnail", side_effect=cancel_then_return
        ):
            late.run()
        self.assertEqual(late_succeeded, [])
        self.assertEqual(late_failed, [])
        self.assertEqual(late_cancelled, [True])

    def test_known_error_uses_one_fixed_safe_message(self):
        worker = LibraryThumbnailWorker("library", self._source("Post_A.jpg"))
        succeeded, failed, cancelled = self._events(worker)
        with mock.patch(
            "workers.load_library_thumbnail",
            side_effect=workers.LibraryThumbnailError(
                r"sensitive D:\private\Post_A.jpg"
            ),
        ):
            worker.run()
        self.assertEqual(succeeded, [])
        self.assertEqual(failed, ["本地缩略图读取失败"])
        self.assertEqual(cancelled, [])

    def test_unknown_error_reports_only_the_exception_type(self):
        worker = LibraryThumbnailWorker("library", self._source("Post_A.jpg"))
        succeeded, failed, cancelled = self._events(worker)
        secret_path = r"D:\private\account-name\Post_A.jpg"
        with mock.patch(
            "workers.load_library_thumbnail",
            side_effect=RuntimeError(secret_path),
        ):
            worker.run()
        self.assertEqual(succeeded, [])
        self.assertEqual(len(failed), 1)
        self.assertIn("RuntimeError", failed[0])
        self.assertNotIn(secret_path, failed[0])
        self.assertNotIn("Post_A.jpg", failed[0])
        self.assertEqual(cancelled, [])


class WorkerLifecycleTests(unittest.TestCase):
    def test_search_cancel_closes_live_api_and_clears_token(self):
        class BlockingAPI:
            def __init__(self):
                self.entered = threading.Event()
                self.closed = threading.Event()
                self.close_count = 0
                self.tokens: list[str] = []

            def search_posts(self, *_args, **_kwargs):
                self.entered.set()
                if not self.closed.wait(3):
                    raise AssertionError("SearchWorker.cancel did not close API")
                raise workers.CancelledError("搜索已取消")

            def close(self):
                self.close_count += 1
                self.closed.set()

            def set_access_token(self, value: str):
                self.tokens.append(value)

        api = BlockingAPI()
        worker = SearchWorker({}, "secret-token", "tag", "", "")
        with mock.patch("workers._api_from_settings", return_value=api):
            thread = threading.Thread(target=worker.run, daemon=True)
            thread.start()
            self.assertTrue(api.entered.wait(1))
            worker.cancel()
            thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(api.close_count, 1)
        self.assertEqual(api.tokens, [""])
        self.assertEqual(worker.token, "")

    def test_pre_cancelled_search_emits_cancelled_without_failure(self):
        worker = SearchWorker({}, "secret-token", "tag", "", "")
        cancelled: list[bool] = []
        failures: list[str] = []
        worker.cancelled.connect(lambda: cancelled.append(True))
        worker.failed.connect(failures.append)
        worker.cancel()

        with mock.patch("workers._api_from_settings") as factory:
            worker.run()

        factory.assert_called_once()
        self.assertEqual(cancelled, [True])
        self.assertEqual(failures, [])
        self.assertEqual(worker.token, "")

    def test_search_cancelled_during_api_return_cannot_emit_success(self):
        worker = SearchWorker({}, "secret-token", "tag", "", "")

        class CancellingAPI:
            def search_posts(self, *_args, **_kwargs):
                worker.stop_event.set()
                return SimpleNamespace(posts=(), next_cursor="cursor")

            def set_access_token(self, _value: str) -> None:
                pass

            def close(self) -> None:
                pass

        succeeded: list[object] = []
        cancelled: list[bool] = []
        failures: list[str] = []
        worker.succeeded.connect(succeeded.append)
        worker.cancelled.connect(lambda: cancelled.append(True))
        worker.failed.connect(failures.append)

        with mock.patch("workers._api_from_settings", return_value=CancellingAPI()):
            worker.run()

        self.assertEqual(succeeded, [])
        self.assertEqual(cancelled, [True])
        self.assertEqual(failures, [])
        self.assertEqual(worker.token, "")

    def test_constructor_failures_emit_errors_and_scrub_secrets(self):
        search = SearchWorker({}, "search-token", "tag", "", "")
        search_errors: list[str] = []
        search.failed.connect(search_errors.append)
        with mock.patch("workers._api_from_settings", side_effect=RuntimeError("boom")):
            search.run()
        self.assertEqual(len(search_errors), 1)
        self.assertEqual(search.token, "")

        login = LoginWorker({}, Credentials("user", "password"))
        login_errors: list[str] = []
        login.failed.connect(login_errors.append)
        with mock.patch("workers._api_from_settings", side_effect=RuntimeError("boom")):
            login.run()
        self.assertEqual(len(login_errors), 1)
        self.assertIsNone(login.credentials)

        thumbnail = ThumbnailWorker(
            9, "789", "https://s.sankakucomplex.com/a.jpg"
        )
        thumbnail_errors: list[tuple] = []
        thumbnail.signals.failed.connect(lambda *args: thumbnail_errors.append(args))
        with mock.patch("workers.Session", side_effect=RuntimeError("boom")):
            thumbnail.run()
        self.assertEqual(thumbnail_errors, [(9, "789")])
        self.assertEqual(thumbnail.url, "")

        download = DownloadWorker(
            {},
            "download-token",
            [workers.DownloadTask("Post_A", "").validated()],
        )
        blocked: list[tuple] = []
        finished: list[tuple] = []
        terminal_events: list[str] = []
        download.batch_blocked.connect(
            lambda *args: (blocked.append(args), terminal_events.append("blocked"))
        )
        download.batch_finished.connect(
            lambda *args: (finished.append(args), terminal_events.append("finished"))
        )
        with mock.patch("workers._api_from_settings", side_effect=RuntimeError("boom")):
            download.run()
        self.assertEqual(blocked[0][0], download)
        self.assertEqual(len(blocked), 1)
        self.assertEqual(finished, [(download, 0, 0, True)])
        self.assertEqual(terminal_events, ["blocked", "finished"])
        self.assertEqual(download.token, "")

    def test_downloader_construction_failure_closes_api_and_finishes_stopped(self):
        class FakeAPI:
            def __init__(self) -> None:
                self.tokens: list[str] = []
                self.closed = False

            def set_access_token(self, value: str) -> None:
                self.tokens.append(value)

            def close(self) -> None:
                self.closed = True

        api = FakeAPI()
        worker = DownloadWorker(
            {},
            "download-token",
            [workers.DownloadTask("Post_A", "").validated()],
        )
        events: list[tuple[str, object]] = []
        worker.batch_blocked.connect(
            lambda *args: events.append(("blocked", args))
        )
        worker.batch_finished.connect(
            lambda *args: events.append(("finished", args))
        )

        with (
            mock.patch("workers._api_from_settings", return_value=api),
            mock.patch(
                "workers.MediaDownloader",
                side_effect=RuntimeError("sensitive constructor detail"),
            ),
        ):
            worker.run()

        self.assertEqual([name for name, _value in events], ["blocked", "finished"])
        self.assertIs(events[0][1][0], worker)
        self.assertNotIn("sensitive constructor detail", str(events[0][1][1]))
        self.assertEqual(events[1][1], (worker, 0, 0, True))
        self.assertEqual(api.tokens, [""])
        self.assertTrue(api.closed)
        self.assertEqual(worker.token, "")

    def test_per_item_access_denial_does_not_block_the_next_download(self):
        for denial in (
            AccessDeniedError("当前账号无权访问该资源"),
            MediaAccessDeniedError("当前作品的签名媒体地址不可用或无权访问"),
        ):
            with self.subTest(error_type=type(denial).__name__):
                class FakeAPI:
                    def __init__(self):
                        self.tokens: list[str] = []
                        self.closed = False

                    def set_access_token(self, value: str) -> None:
                        self.tokens.append(value)

                    def close(self) -> None:
                        self.closed = True

                calls: list[str] = []

                class FakeDownloader:
                    def __init__(self, *_args, **_kwargs):
                        self.closed = False

                    def download(self, post_id: str, *, progress=None):
                        del progress
                        calls.append(post_id)
                        if post_id == "Post_A":
                            raise denial
                        return SimpleNamespace(metadata_warning="")

                    def close(self) -> None:
                        self.closed = True

                api = FakeAPI()
                tasks = [
                    workers.DownloadTask("Post_A", "").validated(),
                    workers.DownloadTask("Post_B", "").validated(),
                ]
                worker = DownloadWorker({}, "download-token", tasks)
                succeeded: list[tuple] = []
                failed: list[tuple] = []
                blocked: list[tuple] = []
                finished: list[tuple] = []
                worker.item_succeeded.connect(lambda *args: succeeded.append(args))
                worker.item_failed.connect(lambda *args: failed.append(args))
                worker.batch_blocked.connect(lambda *args: blocked.append(args))
                worker.batch_finished.connect(lambda *args: finished.append(args))

                with (
                    mock.patch("workers._api_from_settings", return_value=api),
                    mock.patch("workers.MediaDownloader", FakeDownloader),
                ):
                    worker.run()

                self.assertEqual(calls, ["Post_A", "Post_B"])
                self.assertTrue(all(value[0] is worker for value in failed + succeeded))
                self.assertEqual([value[1] for value in failed], ["Post_A"])
                self.assertEqual([value[1] for value in succeeded], ["Post_B"])
                self.assertEqual(blocked, [])
                self.assertEqual(finished, [(worker, 1, 1, False)])
                self.assertEqual(api.tokens, [""])
                self.assertTrue(api.closed)
                self.assertEqual(worker.token, "")

    def test_authentication_and_rate_limit_failures_block_owned_batch(self):
        for failure in (
            AuthenticationError("登录已失效，请重新登录"),
            RateLimitError("请求过于频繁，请稍后重试"),
        ):
            with self.subTest(error_type=type(failure).__name__):
                class FakeAPI:
                    def __init__(self) -> None:
                        self.tokens: list[str] = []
                        self.closed = False

                    def set_access_token(self, value: str) -> None:
                        self.tokens.append(value)

                    def close(self) -> None:
                        self.closed = True

                calls: list[str] = []

                class FakeDownloader:
                    def __init__(self, *_args, **_kwargs) -> None:
                        self.closed = False

                    def download(self, post_id: str, *, progress=None):
                        del progress
                        calls.append(post_id)
                        raise failure

                    def close(self) -> None:
                        self.closed = True

                api = FakeAPI()
                tasks = [
                    workers.DownloadTask("Post_A", "").validated(),
                    workers.DownloadTask("Post_B", "").validated(),
                ]
                worker = DownloadWorker({}, "download-token", tasks)
                failed: list[tuple] = []
                blocked: list[tuple] = []
                finished: list[tuple] = []
                worker.item_failed.connect(lambda *args: failed.append(args))
                worker.batch_blocked.connect(lambda *args: blocked.append(args))
                worker.batch_finished.connect(lambda *args: finished.append(args))

                with (
                    mock.patch("workers._api_from_settings", return_value=api),
                    mock.patch("workers.MediaDownloader", FakeDownloader),
                ):
                    worker.run()

                self.assertEqual(calls, ["Post_A"])
                self.assertEqual(failed, [(worker, "Post_A", str(failure))])
                self.assertEqual(blocked, [(worker, str(failure))])
                self.assertEqual(finished, [(worker, 0, 1, True)])
                self.assertEqual(api.tokens, [""])
                self.assertTrue(api.closed)
                self.assertEqual(worker.token, "")

if __name__ == "__main__":
    unittest.main()
