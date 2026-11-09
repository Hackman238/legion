import configparser
import os
import shlex
import unittest

from app.scheduler.policy import normalize_engagement_policy
from app.scheduler.policy_engine import evaluate_policy_for_risk_tags
from app.scheduler.risk import classify_risk_tags

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _port_actions_from_default_config():
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read(os.path.join(REPO_ROOT, "legion.conf"), encoding="utf-8")
    rows = []
    for key, raw in parser["PortActions"].items():
        fields = [item.strip() for item in shlex.split(raw.replace(",", " , ")) if item.strip() != ","]
        command = next((item for item in fields if item.startswith("nmap ") or " [IP]" in item), "")
        rows.append((key, command or raw))
    return rows


class BruteForceRiskClassificationTest(unittest.TestCase):
    def test_every_bundled_brute_action_is_tagged_as_credential_bruteforce(self):
        rows = [(key, command) for key, command in _port_actions_from_default_config() if "brute" in key.lower()]
        self.assertGreater(len(rows), 10)
        for key, command in rows:
            tags = classify_risk_tags(command, tool_id=key)
            with self.subTest(action=key):
                if key.startswith("dns-brute"):
                    continue  # name enumeration, not password guessing
                self.assertIn("credential_bruteforce", tags)
                if "unsafe=1" in command:
                    self.assertIn("service_instability", tags)

    def test_brute_actions_need_approval_or_are_blocked_under_every_preset(self):
        tags = classify_risk_tags(
            "nmap -Pn [IP] -p [PORT] --script=smb-brute.nse --script-args=unsafe=1", tool_id="smb-brute.nse"
        )
        for preset in ("internal_recon", "external_recon", "external_pentest", "internal_pentest"):
            decision = evaluate_policy_for_risk_tags(tags, normalize_engagement_policy({"preset": preset}))
            with self.subTest(preset=preset):
                self.assertNotEqual("allowed", decision.state)

    def test_plain_enumeration_scripts_are_not_tagged(self):
        self.assertEqual([], classify_risk_tags("nmap -Pn [IP] -p [PORT] --script=smb-os-discovery.nse", tool_id="smb-os-discovery.nse"))
        self.assertNotIn("credential_bruteforce", classify_risk_tags("nmap -Pn [IP] --script=dns-brute.nse", tool_id="dns-brute.nse"))


if __name__ == "__main__":
    unittest.main()
