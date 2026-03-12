from __future__ import annotations

import unittest

from src.fuzzy import fuzzy_match


class HistoryHelpersTests(unittest.TestCase):
    def test_fuzzy_match_handles_short_vendor_fragment(self) -> None:
        self.assertTrue(fuzzy_match("tp", "TP-Link Limited"))

    def test_fuzzy_match_handles_subsequence_queries(self) -> None:
        self.assertTrue(fuzzy_match("tplnk", "TP-Link"))

    def test_fuzzy_match_rejects_unrelated_values(self) -> None:
        self.assertFalse(fuzzy_match("apple", "TP-Link Limited", "Tuya Smart"))


if __name__ == "__main__":
    unittest.main()
