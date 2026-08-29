# -*- coding: utf-8 -*-
"""Offline tests for the embedded browser's fail-closed security helpers."""

from __future__ import annotations

import unittest

import ui_browser_tab as browser


class _EncodedUrl:
    def __init__(self, value: bytes):
        self.value = value

    def toEncoded(self):
        return self.value


class _RequestInfo:
    def __init__(self, url: bytes):
        self.url = _EncodedUrl(url)
        self.blocked: list[bool] = []

    def requestUrl(self):
        return self.url

    def block(self, value: bool) -> None:
        self.blocked.append(value)


class _SignalRecorder:
    def __init__(self):
        self.count = 0

    def emit(self) -> None:
        self.count += 1


class BrowserResourceInterceptorTests(unittest.TestCase):
    def test_allows_exact_first_party_and_cdn_requests(self):
        for url in (
            b"https://chan.sankakucomplex.com/cn/app.js",
            b"https://v.sankakucomplex.com/video.mp4?e=1&m=signed",
            b"https://s.sankakucomplex.com/sample.jpg",
            b"https://cs.sankakucomplex.com/preview.webp",
            b"https://media.sankaku.app/audio.ogg",
            b"data:image/png;base64,AAAA",
        ):
            with self.subTest(url=url):
                info = _RequestInfo(url)
                self.assertTrue(browser._block_untrusted_resource_request(info))
                self.assertEqual(info.blocked, [])

    def test_blocks_third_party_sensitive_and_malformed_requests(self):
        for url in (
            b"https://tracker.example/pixel",
            b"https://cdn.sankakucomplex.com/image.jpg",
            b"https://cs.sankakucomplex.com/image.jpg?token=secret",
            b"file:///C:/private.txt",
            b"http://chan.sankakucomplex.com/insecure.js",
            b"\xff",
        ):
            with self.subTest(url=url):
                info = _RequestInfo(url)
                self.assertFalse(browser._block_untrusted_resource_request(info))
                self.assertEqual(info.blocked, [True])

        class BrokenInfo:
            def __init__(self):
                self.blocked = []

            def requestUrl(self):
                raise RuntimeError("request was destroyed")

            def block(self, value):
                self.blocked.append(value)

        broken = BrokenInfo()
        self.assertFalse(browser._block_untrusted_resource_request(broken))
        self.assertEqual(broken.blocked, [True])


class BrowserPermissionTests(unittest.TestCase):
    def test_rejects_all_supported_request_object_shapes(self):
        for method_name in (
            "deny",
            "reject",
            "cancel",
            "selectNone",
            "rejectCertificate",
        ):
            with self.subTest(method_name=method_name):
                calls = []

                class Request:
                    def __getattr__(self, name):
                        if name == method_name:
                            return lambda: calls.append(name)
                        raise AttributeError(name)

                self.assertTrue(browser._deny_request_object(Request()))
                self.assertEqual(calls, [method_name])

        self.assertFalse(browser._deny_request_object(object()))

    def test_falls_through_when_one_denial_method_is_unusable(self):
        class Request:
            def deny(self):
                raise RuntimeError("stale permission")

            def reject(self):
                self.rejected = True

        request = Request()
        self.assertTrue(browser._deny_request_object(request))
        self.assertTrue(request.rejected)

    @unittest.skipUnless(browser.WEBENGINE_AVAILABLE, "QtWebEngine is unavailable")
    def test_feature_permission_handler_always_denies(self):
        class Page:
            def __init__(self):
                self.calls = []
                self.permission_blocked = _SignalRecorder()

            def setFeaturePermission(self, origin, feature, policy):
                self.calls.append((origin, feature, policy))

        page = Page()
        origin = object()
        feature = object()
        browser._PolicyWebPage._deny_feature_permission(page, origin, feature)
        self.assertEqual(
            page.calls,
            [
                (
                    origin,
                    feature,
                    browser.QWebEnginePage.PermissionPolicy.PermissionDeniedByUser,
                )
            ],
        )
        self.assertEqual(page.permission_blocked.count, 1)

    @unittest.skipUnless(browser.WEBENGINE_AVAILABLE, "QtWebEngine is unavailable")
    def test_file_chooser_is_denied_without_exposing_paths(self):
        class Page:
            def __init__(self):
                self.permission_blocked = _SignalRecorder()

        page = Page()
        result = browser._PolicyWebPage.chooseFiles(
            page,
            object(),
            ["C:/private/previous.txt"],
            ["text/plain"],
        )
        self.assertEqual(result, [])
        self.assertEqual(page.permission_blocked.count, 1)

    @unittest.skipUnless(browser.WEBENGINE_AVAILABLE, "QtWebEngine is unavailable")
    def test_security_settings_disable_privileged_capabilities(self):
        class Settings:
            def __init__(self):
                self.values = {}

            def setAttribute(self, attribute, enabled):
                self.values[attribute.name] = enabled

        settings = Settings()
        browser._harden_webengine_settings(settings)
        for name in (
            "JavascriptCanOpenWindows",
            "JavascriptCanAccessClipboard",
            "JavascriptCanPaste",
            "LocalContentCanAccessRemoteUrls",
            "LocalContentCanAccessFileUrls",
            "FullScreenSupportEnabled",
            "ScreenCaptureEnabled",
            "AllowRunningInsecureContent",
            "AllowGeolocationOnInsecureOrigins",
            "DnsPrefetchEnabled",
            "NavigateOnDropEnabled",
        ):
            with self.subTest(name=name):
                self.assertIs(settings.values[name], False)
        self.assertIs(settings.values["PlaybackRequiresUserGesture"], True)
        self.assertIs(settings.values["WebRTCPublicInterfacesOnly"], True)


if __name__ == "__main__":
    unittest.main()
