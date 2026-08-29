# -*- coding: utf-8 -*-
"""Offline tests for the pure Sankaku URL boundary policy."""

from __future__ import annotations

import unittest

from sankaku_url_policy import (
    MAX_POST_ID_CHARS,
    MAX_TAG_QUERY_CHARS,
    MAX_URL_CHARS,
    canonical_post_url,
    is_allowed_browser_resource_url,
    is_allowed_media_host,
    is_allowed_page_host,
    normalize_media_url,
    normalize_page_url,
    normalize_post_id,
    normalize_tag_query,
    post_id_from_url,
    tag_search_url,
)


class _EncodedUrl:
    def __init__(self, payload):
        self.payload = payload

    def toEncoded(self):
        return self.payload


class SankakuHostPolicyTests(unittest.TestCase):
    def test_page_hosts_are_an_exact_allowlist(self):
        accepted = {
            "chan.sankakucomplex.com",
            "www.sankakucomplex.com",
            "beta.sankakucomplex.com",
            "black.sankakucomplex.com",
            "white.sankakucomplex.com",
            "login.sankakucomplex.com",
            "sankaku.app",
            " CHAN.SANKAKUCOMPLEX.COM. ",
        }
        for host in accepted:
            with self.subTest(host=host):
                self.assertTrue(is_allowed_page_host(host))

        rejected = {
            "sankakucomplex.com",
            "cdn.sankakucomplex.com",
            "chan.sankakucomplex.com.evil.example",
            "evilchan.sankakucomplex.com",
            "sankaku.app.evil.example",
            "",
            "例.example",
            "bad_host.sankaku.app",
        }
        for host in rejected:
            with self.subTest(host=host):
                self.assertFalse(is_allowed_page_host(host))
        self.assertFalse(is_allowed_page_host(None))

    def test_media_hosts_are_an_exact_cdn_allowlist(self):
        for host in (
            "v.sankakucomplex.com",
            "s.sankakucomplex.com",
            "cs.sankakucomplex.com",
            "media.sankaku.app",
            " MEDIA.SANKAKU.APP. ",
        ):
            with self.subTest(host=host):
                self.assertTrue(is_allowed_media_host(host))

        for host in (
            "sankakucomplex.com",
            "a.b.sankakucomplex.com",
            "login.sankakucomplex.com",
            "sankaku.app",
            "sankakucomplex.com.example",
            "not-sankakucomplex.com",
            "sankaku.app.example",
            "bad_host.sankaku.app",
            "",
        ):
            with self.subTest(host=host):
                self.assertFalse(is_allowed_media_host(host))


class SankakuPageUrlTests(unittest.TestCase):
    def test_normalizes_relative_and_scheme_less_urls(self):
        self.assertEqual(
            normalize_page_url("/cn/posts/abc_123#preview"),
            "https://chan.sankakucomplex.com/cn/posts/abc_123",
        )
        self.assertEqual(
            normalize_page_url(
                "CHAN.SANKAKUCOMPLEX.COM.:443/cn/?tags=cat%20girl&empty=#frag",
                keep_fragment=True,
            ),
            "https://chan.sankakucomplex.com/cn/?tags=cat+girl&empty=#frag",
        )

    def test_accepts_qurl_like_ascii_encoding(self):
        value = _EncodedUrl(b"https://chan.sankakucomplex.com/en/posts/A-1")
        self.assertEqual(
            normalize_page_url(value),
            "https://chan.sankakucomplex.com/en/posts/A-1",
        )
        self.assertIsNone(normalize_page_url(_EncodedUrl(b"\xff")))
        self.assertIsNone(normalize_page_url(_EncodedUrl(None)))

    def test_rejects_unsafe_page_urls(self):
        rejected = (
            "http://chan.sankakucomplex.com/cn/",
            "https://user:pass@chan.sankakucomplex.com/cn/",
            "https://chan.sankakucomplex.com:444/cn/",
            "https://cdn.sankakucomplex.com/image.jpg",
            "https://chan.sankakucomplex.com.evil.example/cn/",
            "https://chan.sankakucomplex.com\\@evil.example/cn/",
            "https://chan.sankakucomplex.com/cn/?token=secret",
            "https://chan.sankakucomplex.com/cn/?ToKeN=secret",
            "https://chan.sankakucomplex.com/cn/?to%6ben=secret",
            "https://chan.sankakucomplex.com/cn/?authorization=secret",
            "https://chan.sankakucomplex.com/cn/\nnext",
            " ",
        )
        for value in rejected:
            with self.subTest(value=value):
                self.assertIsNone(normalize_page_url(value))
        self.assertIsNone(normalize_page_url(None))

    def test_url_character_limit_is_inclusive(self):
        prefix = "https://chan.sankakucomplex.com/"
        at_limit = prefix + ("a" * (MAX_URL_CHARS - len(prefix)))
        self.assertEqual(normalize_page_url(at_limit), at_limit)
        self.assertIsNone(normalize_page_url(at_limit + "a"))

    def test_fragment_policy_is_explicit(self):
        url = "https://chan.sankakucomplex.com/cn/posts/42#details"
        self.assertEqual(
            normalize_page_url(url),
            "https://chan.sankakucomplex.com/cn/posts/42",
        )
        self.assertEqual(normalize_page_url(url, keep_fragment=True), url)
        self.assertIsNone(
            normalize_page_url(
                "https://chan.sankakucomplex.com/cn/#access_token=secret",
                keep_fragment=True,
            )
        )
        self.assertIsNone(
            normalize_page_url(
                "https://chan.sankakucomplex.com/sso/callback?code=secret"
            )
        )


class SankakuMediaUrlTests(unittest.TestCase):
    def test_preserves_signed_media_query_exactly(self):
        value = (
            "https://cs.sankakucomplex.com/data/sample.jpg"
            "?e=1700000000&m=AbC%2Fdef+ghi"
        )
        self.assertEqual(normalize_media_url(f"  {value}  "), value)
        self.assertEqual(
            normalize_media_url("https://media.sankaku.app:443/a.png?x=1&x=2"),
            "https://media.sankaku.app:443/a.png?x=1&x=2",
        )

    def test_rejects_unsafe_media_urls(self):
        for value in (
            "http://cs.sankakucomplex.com/a.jpg",
            "https://u:p@cs.sankakucomplex.com/a.jpg",
            "https://cs.sankakucomplex.com:444/a.jpg",
            "https://sankakucomplex.com.example/a.jpg",
            "https://a.b.sankakucomplex.com/a.jpg",
            "https://login.sankakucomplex.com/a.jpg",
            "https://example.com/a.jpg",
            "https://cs.sankakucomplex.com\\@example.com/a.jpg",
            "https://cs.sankakucomplex.com/a.jpg?access_token=secret",
            "https://cs.sankakucomplex.com/a.jpg?to%6ben=secret",
            "https://cs.sankakucomplex.com/a.jpg?x=1;authorization=secret",
            "https://cs.sankakucomplex.com/a.jpg#refresh_token=secret",
            "https://cs.sankakucomplex.com/a.jpg\rnext",
            "",
        ):
            with self.subTest(value=value):
                self.assertIsNone(normalize_media_url(value))
        self.assertIsNone(normalize_media_url(object()))

    def test_media_url_character_limit_is_inclusive(self):
        prefix = "https://cs.sankakucomplex.com/"
        at_limit = prefix + ("a" * (MAX_URL_CHARS - len(prefix)))
        self.assertEqual(normalize_media_url(at_limit), at_limit)
        self.assertIsNone(normalize_media_url(at_limit + "a"))

    def test_browser_resource_policy_blocks_third_parties_and_secrets(self):
        accepted = (
            "https://chan.sankakucomplex.com/cn/app.js?v=1",
            "https://login.sankakucomplex.com/style.css",
            "https://v.sankakucomplex.com/video.mp4?e=1&m=signature",
            "https://s.sankakucomplex.com/sample.jpg",
            "https://cs.sankakucomplex.com/preview.webp",
            "https://media.sankaku.app/audio.ogg",
            "about:blank",
            "about:srcdoc",
            "data:image/png;base64,AAAA",
            "blob:https://chan.sankakucomplex.com/550e8400-e29b-41d4-a716-446655440000",
        )
        for value in accepted:
            with self.subTest(value=value):
                self.assertTrue(is_allowed_browser_resource_url(value))

        rejected = (
            "http://chan.sankakucomplex.com/app.js",
            "https://evil.example/tracker.js",
            "https://cdn.sankakucomplex.com/image.jpg",
            "https://cs.sankakucomplex.com/image.jpg?password=secret",
            "https://chan.sankakucomplex.com/app.js?code=secret",
            "blob:https://evil.example/id",
            "file:///C:/sensitive.txt",
            "javascript:alert(1)",
            "about:config",
        )
        for value in rejected:
            with self.subTest(value=value):
                self.assertFalse(is_allowed_browser_resource_url(value))
        self.assertFalse(is_allowed_browser_resource_url(_EncodedUrl(b"\xff")))


class SankakuPostAndTagPolicyTests(unittest.TestCase):
    def test_post_ids_and_canonical_urls(self):
        maximum = "A" + ("b" * (MAX_POST_ID_CHARS - 1))
        self.assertEqual(normalize_post_id(f"  {maximum}  "), maximum)
        self.assertIsNone(normalize_post_id(maximum + "c"))
        self.assertIsNone(normalize_post_id("-starts-with-dash"))
        self.assertIsNone(normalize_post_id("has space"))
        self.assertIsNone(normalize_post_id(""))
        self.assertIsNone(normalize_post_id(123))

        self.assertEqual(
            canonical_post_url("abc_123-Z", locale="ja"),
            "https://chan.sankakucomplex.com/ja/posts/abc_123-Z",
        )
        self.assertEqual(
            canonical_post_url("abc_123-Z", locale="unsupported"),
            "https://chan.sankakucomplex.com/cn/posts/abc_123-Z",
        )

    def test_extracts_supported_post_path_forms(self):
        cases = {
            "https://chan.sankakucomplex.com/cn/posts/123": "123",
            "https://chan.sankakucomplex.com/en/post/abc_1": "abc_1",
            "https://chan.sankakucomplex.com/cn/post/show/legacy_9": "legacy_9",
            "https://chan.sankakucomplex.com/posts/A-B/": "A-B",
            "https://beta.sankakucomplex.com/POSTS/MixedCase": "MixedCase",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(post_id_from_url(url), expected)
        self.assertIsNone(post_id_from_url("https://example.com/posts/123"))
        self.assertIsNone(post_id_from_url("https://chan.sankakucomplex.com/cn/"))

    def test_canonical_url_accepts_an_official_post_url(self):
        self.assertEqual(
            canonical_post_url(
                "https://beta.sankakucomplex.com/en/post/source_7?ignored=1",
                locale="en",
            ),
            "https://chan.sankakucomplex.com/en/posts/source_7",
        )

    def test_tag_query_nfkc_and_search_encoding(self):
        self.assertEqual(normalize_tag_query("  ＣＡＴ　girl  "), "CAT girl")
        self.assertEqual(
            tag_search_url("cat girl -rating:e", locale="en"),
            "https://chan.sankakucomplex.com/en/?tags=cat+girl+-rating%3Ae",
        )
        self.assertEqual(
            tag_search_url("猫", locale="bad"),
            "https://chan.sankakucomplex.com/cn/?tags=%E7%8C%AB",
        )

    def test_tag_query_boundaries_and_control_characters(self):
        at_limit = "😀" * MAX_TAG_QUERY_CHARS
        self.assertEqual(normalize_tag_query(at_limit), at_limit)
        self.assertIsNone(normalize_tag_query(at_limit + "😀"))
        self.assertIsNone(normalize_tag_query("tag\nother"))
        self.assertIsNone(normalize_tag_query("tag\u200bother"))
        self.assertIsNone(normalize_tag_query(None))


if __name__ == "__main__":
    unittest.main()
