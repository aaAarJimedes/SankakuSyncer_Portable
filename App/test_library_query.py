# -*- coding: utf-8 -*-
"""Offline tests for deterministic local-library filtering and sorting."""

from __future__ import annotations

import itertools
import unittest

from library_query import LibraryQueryError, query_library_entries
from local_library import LibraryEntry


def _entry(
    post_id: str,
    *,
    status: str = "verified",
    path: str | None = None,
    size: int = 1,
    author: str = "",
    tags: tuple[str, ...] = (),
    created_at: str = "",
) -> LibraryEntry:
    return LibraryEntry(
        status=status,
        post_id=post_id,
        variant="original",
        relative_path=path or f"{post_id}.jpg",
        size=size,
        content_type="image/jpeg",
        rating="s",
        author=author,
        tags=tags,
        created_at=created_at,
        detail="",
    )


class LibraryQueryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entries = (
            _entry(
                "Post_B",
                size=50,
                author="Artist One",
                tags=("Blue_Eyes", "landscape"),
                created_at="1700000000",
            ),
            _entry(
                "Post_A",
                status="changed",
                path="Post_A.sample.png",
                size=100,
                author="Artist Two",
                tags=("portrait",),
                created_at="2026-08-29T10:00:00Z",
            ),
            _entry("Post_C", size=10, created_at="unknown"),
        )

    def test_text_tokens_match_id_author_tags_and_filename_without_mutation(self):
        original = tuple(self.entries)
        self.assertEqual(
            [entry.post_id for entry in query_library_entries(self.entries, query="artist blue")],
            ["Post_B"],
        )
        self.assertEqual(
            [entry.post_id for entry in query_library_entries(self.entries, query="sample.png")],
            ["Post_A"],
        )
        self.assertEqual(self.entries, original)

    def test_query_uses_nfkc_and_casefold(self):
        result = query_library_entries(self.entries, query="ＢＬＵＥ_ＥＹＥＳ")
        self.assertEqual([entry.post_id for entry in result], ["Post_B"])
        compatibility_entry = _entry("Post_D", author="ＡＲＴＩＳＴ")
        self.assertEqual(
            query_library_entries((compatibility_entry,), query="artist"),
            (compatibility_entry,),
        )

    def test_status_filter_combines_with_text_query(self):
        self.assertEqual(
            [
                entry.post_id
                for entry in query_library_entries(
                    self.entries, status="changed", query="artist"
                )
            ],
            ["Post_A"],
        )
        self.assertEqual(
            query_library_entries(self.entries, status="missing_media"), ()
        )

    def test_all_sort_modes_are_deterministic(self):
        self.assertEqual(
            [entry.post_id for entry in query_library_entries(self.entries)],
            ["Post_A", "Post_B", "Post_C"],
        )

    def test_numeric_post_ids_sort_by_value(self):
        entries = (_entry("10"), _entry("2"), _entry("001"))
        self.assertEqual(
            [
                entry.post_id
                for entry in query_library_entries(entries, sort="id_asc")
            ],
            ["001", "2", "10"],
        )

    def test_casefold_collisions_do_not_depend_on_input_order(self):
        upper = _entry("Case", path="Case.jpg", author="upper")
        lower = _entry("case", path="case.jpg", author="lower")
        same_identity_a = _entry("same", path="same.jpg", author="A")
        same_identity_b = _entry("same", path="same.jpg", author="B")
        forward = (lower, same_identity_b, upper, same_identity_a)
        backward = tuple(reversed(forward))
        for sort in ("id_asc", "id_desc", "newest", "largest"):
            with self.subTest(sort=sort):
                self.assertEqual(
                    query_library_entries(forward, sort=sort),
                    query_library_entries(backward, sort=sort),
                )
        self.assertEqual(
            [
                entry.post_id
                for entry in query_library_entries(self.entries, sort="id_desc")
            ],
            ["Post_C", "Post_B", "Post_A"],
        )
        self.assertEqual(
            [
                entry.post_id
                for entry in query_library_entries(self.entries, sort="largest")
            ],
            ["Post_A", "Post_B", "Post_C"],
        )
        self.assertEqual(
            [
                entry.post_id
                for entry in query_library_entries(self.entries, sort="newest")
            ],
            ["Post_A", "Post_B", "Post_C"],
        )

    def test_invalid_status_sort_query_type_length_and_controls_are_rejected(self):
        cases = (
            {"status": "unknown"},
            {"status": None},
            {"sort": "unknown"},
            {"sort": None},
            {"query": None},
            {"query": "x" * 257},
            {"query": "\ufb03" * 100},
            {"query": "bad\x00query"},
            {"query": "\n"},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(LibraryQueryError):
                query_library_entries(self.entries, **values)

    def test_entry_iterables_are_type_checked_and_bounded(self):
        with self.assertRaisesRegex(LibraryQueryError, "格式无效"):
            query_library_entries((*self.entries, object()))
        with self.assertRaisesRegex(LibraryQueryError, "超过安全上限"):
            query_library_entries(itertools.repeat(self.entries[0]))


if __name__ == "__main__":
    unittest.main()
