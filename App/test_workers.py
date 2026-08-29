# -*- coding: utf-8 -*-
"""Offline tests for thumbnail worker pacing and cancellation."""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
import threading
import unittest
from unittest import mock

import workers
from credential_vault import Credentials
from download_engine import MediaAccessDeniedError
from sankaku_api import AccessDeniedError
from workers import (
    DownloadWorker,
    LoginWorker,
    SearchWorker,
    ThumbnailWorker,
    _thumbnail_payload_allowed,
    _thumbnail_retry_after_seconds,
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


class ThumbnailRetryAfterTests(unittest.TestCase):
    def test_numeric_http_date_reset_and_default_values(self):
        self.assertEqual(_thumbnail_retry_after_seconds({"Retry-After": "12"}), 12.0)
        self.assertEqual(_thumbnail_retry_after_seconds({"Retry-After": "999999"}), 86_400.0)
        with mock.patch("workers.time.time", return_value=1_000.0):
            self.assertEqual(
                _thumbnail_retry_after_seconds(
                    {"Retry-After": "Thu, 01 Jan 1970 00:20:00 GMT"}
                ),
                200.0,
            )
            self.assertEqual(
                _thumbnail_retry_after_seconds({"X-RateLimit-Reset": "1300"}),
                300.0,
            )
        self.assertEqual(_thumbnail_retry_after_seconds({"Retry-After": "broken"}), 600.0)
        self.assertEqual(_thumbnail_retry_after_seconds(object()), 600.0)


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
            headers={"Content-Type": "image/jpeg", "Content-Length": "7"},
            chunks=[b"\xff\xd8\xffabc", b"d"],
        )
        worker, session, gate, succeeded, failed = self._run(response)
        self.assertEqual(succeeded, [(7, "123", b"\xff\xd8\xffabcd")])
        self.assertEqual(failed, [])
        self.assertEqual(gate.min_intervals, [0.5])
        self.assertFalse(session.trust_env)
        self.assertEqual(session.gets[0][1]["headers"]["Accept-Encoding"], "identity")
        self.assertFalse(session.gets[0][1]["allow_redirects"])
        self.assertTrue(response.closed)

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
            ("image/jpeg; charset=binary", b"\xff\xd8\xffx"),
            ("image/png", b"\x89PNG\r\n\x1a\nrest"),
            ("image/gif", b"GIF89arest"),
            ("image/webp", b"RIFF\x04\x00\x00\x00WEBPdata"),
        )
        for content_type, payload in accepted:
            with self.subTest(content_type=content_type):
                self.assertTrue(_thumbnail_payload_allowed(content_type, payload))
        self.assertFalse(
            _thumbnail_payload_allowed("image/png", b"\xff\xd8\xffnot-png")
        )

    def test_rate_limit_defers_the_process_gate_and_fails_closed(self):
        response = FakeResponse(429, headers={"Retry-After": "30"})
        _worker, _session, gate, succeeded, failed = self._run(response)
        self.assertEqual(gate.deferred, [30.0])
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

        download = DownloadWorker({}, "download-token", [])
        blocked: list[str] = []
        finished: list[tuple] = []
        download.batch_blocked.connect(blocked.append)
        download.batch_finished.connect(lambda *args: finished.append(args))
        with mock.patch("workers._api_from_settings", side_effect=RuntimeError("boom")):
            download.run()
        self.assertEqual(len(blocked), 1)
        self.assertEqual(finished, [(0, 0, False)])
        self.assertEqual(download.token, "")

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
                blocked: list[str] = []
                finished: list[tuple] = []
                worker.item_succeeded.connect(lambda *args: succeeded.append(args))
                worker.item_failed.connect(lambda *args: failed.append(args))
                worker.batch_blocked.connect(blocked.append)
                worker.batch_finished.connect(lambda *args: finished.append(args))

                with (
                    mock.patch("workers._api_from_settings", return_value=api),
                    mock.patch("workers.MediaDownloader", FakeDownloader),
                ):
                    worker.run()

                self.assertEqual(calls, ["Post_A", "Post_B"])
                self.assertEqual([value[0] for value in failed], ["Post_A"])
                self.assertEqual([value[0] for value in succeeded], ["Post_B"])
                self.assertEqual(blocked, [])
                self.assertEqual(finished, [(1, 1, False)])
                self.assertEqual(api.tokens, [""])
                self.assertTrue(api.closed)
                self.assertEqual(worker.token, "")

if __name__ == "__main__":
    unittest.main()
