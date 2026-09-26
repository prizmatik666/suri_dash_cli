import unittest
from types import SimpleNamespace

import sdash


class DnsQueryNameTests(unittest.TestCase):
    def test_prefers_suricata_v3_queries(self):
        dns = {
            "queries": [{"rrname": "graph.instagram.com.", "rrtype": "A"}],
            "rrname": "legacy.example",
        }

        self.assertEqual(sdash.dns_query_name(dns), "graph.instagram.com")

    def test_uses_later_valid_query_when_earlier_entries_are_malformed(self):
        dns = {
            "queries": [None, "bad", {}, {"rrname": "valid.example"}],
            "rrname": "legacy.example",
        }

        self.assertEqual(sdash.dns_query_name(dns), "valid.example")

    def test_falls_back_to_top_level_rrname(self):
        malformed_queries = (
            None,
            [],
            {},
            "bad",
            [None],
            [{"rrname": 42}],
            [{"rrname": "."}],
        )

        for queries in malformed_queries:
            with self.subTest(queries=queries):
                dns = {"queries": queries, "rrname": "legacy.example"}
                self.assertEqual(sdash.dns_query_name(dns), "legacy.example")

    def test_preserves_older_nested_query_compatibility(self):
        dns = {"query": {"rrname": "nested.example."}}

        self.assertEqual(sdash.dns_query_name(dns), "nested.example")

    def test_returns_placeholder_only_when_no_name_can_be_recovered(self):
        malformed_dns_values = (None, [], "bad", {}, {"queries": [None, {}]})

        for dns in malformed_dns_values:
            with self.subTest(dns=dns):
                self.assertEqual(sdash.dns_query_name(dns), "?")


class DnsRenderingTests(unittest.TestCase):
    def setUp(self):
        self.original_args = sdash.ARGS
        sdash.ARGS = SimpleNamespace(
            full_ip=False,
            hide_dns_events=False,
            suppress_dns=False,
        )

    def tearDown(self):
        sdash.ARGS = self.original_args

    def test_renders_v3_request_name_after_source_ip(self):
        event = {
            "event_type": "dns",
            "src_ip": "192.168.2.22",
            "dest_ip": "192.168.2.4",
            "dest_port": 53,
            "dns": {
                "version": 3,
                "type": "request",
                "queries": [{"rrname": "graph.instagram.com", "rrtype": "A"}],
            },
        }

        self.assertEqual(
            sdash.summarize(event),
            "???????? DNS   192.168.2.22 -> graph.instagram.com",
        )

    def test_renders_v3_response_name_after_response_source_ip(self):
        event = {
            "event_type": "dns",
            "src_ip": "192.168.2.4",
            "dest_ip": "192.168.2.22",
            "src_port": 53,
            "dns": {
                "version": 3,
                "type": "response",
                "queries": [{"rrname": "graph.instagram.com", "rrtype": "A"}],
            },
        }

        self.assertEqual(
            sdash.summarize(event),
            "???????? DNS   192.168.2.4 -> graph.instagram.com",
        )


if __name__ == "__main__":
    unittest.main()
