import unittest

from app.web.runtime import WebRuntime


class TestWebRuntimeSubnetRescan(unittest.TestCase):
    def test_best_scan_submission_prefers_exact_subnet_match(self):
        records = [
            {
                "id": 1,
                "submission_kind": "nmap_scan",
                "targets": ["10.0.0.5"],
                "scan_mode": "easy",
            },
            {
                "id": 2,
                "submission_kind": "nmap_scan",
                "targets": ["10.0.0.0/24", "10.0.1.0/24"],
                "scan_mode": "hard",
            },
            {
                "id": 3,
                "submission_kind": "nmap_scan",
                "targets": ["10.0.0.0/16"],
                "scan_mode": "legacy",
            },
        ]

        best = WebRuntime._best_scan_submission_for_subnet("10.0.0.0/24", records)

        self.assertIsNotNone(best)
        self.assertEqual(2, best["id"])
        self.assertEqual("hard", best["scan_mode"])

    def test_scan_target_match_score_recognizes_host_within_subnet(self):
        self.assertEqual(50, WebRuntime._scan_target_match_score_for_subnet("10.0.0.25", "10.0.0.0/24"))
        self.assertEqual(-1, WebRuntime._scan_target_match_score_for_subnet("10.1.0.25", "10.0.0.0/24"))
