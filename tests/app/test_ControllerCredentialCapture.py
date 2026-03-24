import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from controller.controller import Controller


class ControllerCredentialCaptureTest(unittest.TestCase):
    def test_extract_credential_capture_entries_parses_ntlmrelay_auth_success(self):
        entries = Controller._extractCredentialCaptureEntries(
            "ntlmrelay",
            "[*] Authenticating against smb://192.168.3.50 as CORP/jdoe SUCCEED",
            default_source="192.168.3.50",
        )

        self.assertEqual(1, len(entries))
        self.assertEqual("smb://192.168.3.50", entries[0]["source"])
        self.assertEqual("CORP/jdoe", entries[0]["username"])
        self.assertEqual("", entries[0]["hash_value"])

    def test_extract_credential_capture_entries_parses_ntlmrelay_sam_hash_line(self):
        line = "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
        entries = Controller._extractCredentialCaptureEntries(
            "ntlmrelay",
            line,
            default_source="192.168.3.50",
        )

        self.assertEqual(1, len(entries))
        self.assertEqual("192.168.3.50", entries[0]["source"])
        self.assertEqual("Administrator", entries[0]["username"])
        self.assertEqual(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            entries[0]["hash_value"],
        )

    def test_extract_credential_capture_entries_ignores_ntlmrelay_noise(self):
        entries = Controller._extractCredentialCaptureEntries(
            "ntlmrelay",
            "[*] SMBD-Thread-5: Received connection from 192.168.3.10, attacking target smb://192.168.3.50",
            default_source="192.168.3.50",
        )

        self.assertEqual([], entries)

    def test_extract_credential_capture_entries_preserves_generic_responder_capture(self):
        entries = Controller._extractCredentialCaptureEntries(
            "responder",
            "alice::CORP:1122334455667788:deadbeef:cafebabe",
            default_source="eth0",
        )

        self.assertEqual(1, len(entries))
        self.assertEqual("eth0", entries[0]["source"])
        self.assertEqual("alice", entries[0]["username"])
        self.assertEqual("CORP:1122334455667788:deadbeef:cafebabe", entries[0]["hash_value"])

    def test_extract_credential_capture_entries_parses_responder_multiline_hash_block(self):
        context = {}

        self.assertEqual(
            [],
            Controller._extractCredentialCaptureEntries(
                "responder",
                "[SMB] NTLMv2-SSP Client   : 192.168.3.25",
                default_source="eth0",
                context=context,
            ),
        )
        self.assertEqual(
            [],
            Controller._extractCredentialCaptureEntries(
                "responder",
                "[SMB] NTLMv2-SSP Username : CORP\\alice",
                default_source="eth0",
                context=context,
            ),
        )

        entries = Controller._extractCredentialCaptureEntries(
            "responder",
            "[SMB] NTLMv2-SSP Hash     : alice::CORP:1122334455667788:deadbeef:cafebabe",
            default_source="eth0",
            context=context,
        )

        self.assertEqual(1, len(entries))
        self.assertEqual("192.168.3.25", entries[0]["source"])
        self.assertEqual("CORP\\alice", entries[0]["username"])
        self.assertEqual("CORP:1122334455667788:deadbeef:cafebabe", entries[0]["hash_value"])

    def test_extract_credential_capture_entries_parses_responder_cleartext_password(self):
        context = {"source": "192.168.3.44", "username": "CORP\\bob"}

        entries = Controller._extractCredentialCaptureEntries(
            "responder",
            "[FTP] Clear Text Password : Password123!",
            default_source="eth0",
            context=context,
        )

        self.assertEqual(1, len(entries))
        self.assertEqual("192.168.3.44", entries[0]["source"])
        self.assertEqual("CORP\\bob", entries[0]["username"])
        self.assertEqual("", entries[0]["hash_value"])
