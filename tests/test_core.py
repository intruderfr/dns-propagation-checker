"""
Basic unit tests for dns-propagation-checker.

Run with: python -m unittest discover -s tests
"""
import unittest
from unittest.mock import patch, MagicMock

from dns_propagation_checker import (
    QueryResult,
    resolvers_from_cli,
    DEFAULT_RESOLVERS,
    _expect_check,
    _fmt_values,
    build_arg_parser,
    SUPPORTED_TYPES,
)


class QueryResultTests(unittest.TestCase):
    def test_ok_when_values_present(self):
        r = QueryResult(
            resolver="x", ip="1.1.1.1", provider="p", region="r",
            record_type="A", domain="example.com", values=["1.2.3.4"], ttl=60,
        )
        self.assertTrue(r.ok)

    def test_not_ok_when_error_set(self):
        r = QueryResult(
            resolver="x", ip="1.1.1.1", provider="p", region="r",
            record_type="A", domain="example.com", error="TIMEOUT",
        )
        self.assertFalse(r.ok)

    def test_fingerprint_sorts_values(self):
        r1 = QueryResult(
            resolver="a", ip="1", provider="p", region="r",
            record_type="A", domain="d", values=["1.1.1.1", "2.2.2.2"],
        )
        r2 = QueryResult(
            resolver="b", ip="2", provider="p", region="r",
            record_type="A", domain="d", values=["2.2.2.2", "1.1.1.1"],
        )
        self.assertEqual(r1.fingerprint, r2.fingerprint)

    def test_fingerprint_distinguishes_errors(self):
        r = QueryResult(
            resolver="a", ip="1", provider="p", region="r",
            record_type="A", domain="d", error="NXDOMAIN",
        )
        self.assertTrue(r.fingerprint.startswith("ERROR:"))


class ResolverParsingTests(unittest.TestCase):
    def test_default_when_none(self):
        self.assertEqual(resolvers_from_cli(None), DEFAULT_RESOLVERS)

    def test_default_when_empty(self):
        self.assertEqual(resolvers_from_cli(""), DEFAULT_RESOLVERS)

    def test_custom_list(self):
        got = resolvers_from_cli("1.1.1.1, 8.8.8.8")
        self.assertEqual(len(got), 2)
        self.assertEqual(got[0][1], "1.1.1.1")
        self.assertEqual(got[1][1], "8.8.8.8")
        self.assertTrue(all(x[2] == "custom" for x in got))


class ExpectCheckTests(unittest.TestCase):
    def _mk(self, values, error=None):
        return QueryResult(
            resolver="r", ip="i", provider="p", region="g",
            record_type="A", domain="d", values=values or [], error=error,
        )

    def test_no_expected_always_ok(self):
        self.assertTrue(_expect_check([self._mk(["1.2.3.4"])], []))

    def test_matches_when_superset(self):
        r = [self._mk(["1.2.3.4", "5.6.7.8"])]
        self.assertTrue(_expect_check(r, ["1.2.3.4"]))

    def test_fails_on_missing_value(self):
        r = [self._mk(["1.2.3.4"])]
        self.assertFalse(_expect_check(r, ["9.9.9.9"]))

    def test_fails_on_error(self):
        r = [self._mk([], error="TIMEOUT")]
        self.assertFalse(_expect_check(r, ["1.2.3.4"]))

    def test_quoted_txt_match(self):
        # TXT records often come back as '"v=spf1 ..."'
        r = [self._mk(['"v=spf1 include:_spf.example.com ~all"'])]
        self.assertTrue(
            _expect_check(r, ["v=spf1 include:_spf.example.com ~all"])
        )


class FormatTests(unittest.TestCase):
    def test_empty_values(self):
        self.assertEqual(_fmt_values([]), "-")

    def test_truncates_long(self):
        out = _fmt_values(["x" * 500], max_width=20)
        self.assertLessEqual(len(out), 20)
        self.assertTrue(out.endswith("…"))


class ArgParserTests(unittest.TestCase):
    def test_parser_defaults(self):
        ns = build_arg_parser().parse_args(["example.com"])
        self.assertEqual(ns.domain, "example.com")
        self.assertEqual(ns.type, "A")
        self.assertIn(ns.type, SUPPORTED_TYPES)
        self.assertEqual(ns.watch, 0)


if __name__ == "__main__":
    unittest.main()
