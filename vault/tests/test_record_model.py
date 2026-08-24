"""Tests for vault.records.record_model.

Uses a hand-built envelope-shaped dict (which crypto.envelope.is_envelope
accepts) so these tests never need to run the KDF or seal anything for real --
they exercise the record model's shape/validation logic directly.
"""
import unittest

from vault.records.record_model import (
    VaultRecordError,
    new_record,
    normalize_label,
    public_summary,
    replace_payload,
    validate_record,
)

_ALGORITHM = "BSR2-ARX-SPONGE-ETM"


def _fake_envelope():
    return {
        "algorithm": _ALGORITHM,
        "version": 2,
        "salt": "00" * 32,
        "nonce": "00" * 32,
        "ciphertext": "00" * 256,
        "tag": "00" * 32,
    }


def _timestamps(created="2026-08-24T10:00:00+00:00", updated="2026-08-24T10:00:00+00:00"):
    return {"created_at": created, "updated_at": updated}


class LabelNormalizationTests(unittest.TestCase):
    def test_strips_surrounding_whitespace(self):
        self.assertEqual(normalize_label("  Wi-Fi  "), "Wi-Fi")

    def test_nfkc_folds_composition_variants(self):
        self.assertEqual(normalize_label("Caf\u00e9"), normalize_label("Cafe\u0301"))

    def test_empty_label_is_rejected(self):
        with self.assertRaises(VaultRecordError):
            normalize_label("   ")

    def test_non_string_label_is_rejected(self):
        with self.assertRaises(VaultRecordError):
            normalize_label(1234)

    def test_overlong_label_is_rejected(self):
        with self.assertRaises(VaultRecordError):
            normalize_label("x" * 300)


class RecordConstructionTests(unittest.TestCase):
    def test_new_record_has_expected_shape(self):
        record = new_record("rid-1", "Email", "credential", _fake_envelope(), _timestamps())
        self.assertEqual(record["record_id"], "rid-1")
        self.assertEqual(record["kind"], "credential")
        self.assertEqual(record["label"], "Email")

    def test_new_record_rejects_non_envelope_payload(self):
        with self.assertRaises(VaultRecordError):
            new_record("rid-1", "Email", "credential", {"not": "envelope"}, _timestamps())

    def test_new_record_rejects_empty_record_id(self):
        with self.assertRaises(VaultRecordError):
            new_record("", "Email", "credential", _fake_envelope(), _timestamps())

    def test_new_record_requires_both_timestamps(self):
        with self.assertRaises(VaultRecordError):
            new_record("rid-1", "Email", "credential", _fake_envelope(), {"created_at": "x"})

    def test_overlong_kind_is_rejected(self):
        with self.assertRaises(VaultRecordError):
            new_record("rid-1", "Email", "k" * 100, _fake_envelope(), _timestamps())


class RecordValidationTests(unittest.TestCase):
    def setUp(self):
        self.record = new_record("rid-1", "Email", "credential", _fake_envelope(), _timestamps())

    def test_a_good_record_validates(self):
        self.assertEqual(validate_record(self.record), self.record)

    def test_non_dict_is_rejected(self):
        with self.assertRaises(VaultRecordError):
            validate_record(["not", "a", "record"])

    def test_wrong_format_is_rejected(self):
        broken = dict(self.record)
        broken["format"] = "something-else"
        with self.assertRaises(VaultRecordError):
            validate_record(broken)

    def test_missing_payload_envelope_is_rejected(self):
        broken = dict(self.record)
        broken["payload"] = {"not": "envelope"}
        with self.assertRaises(VaultRecordError):
            validate_record(broken)


class ReplacePayloadTests(unittest.TestCase):
    def test_replace_payload_returns_a_copy_and_does_not_mutate(self):
        record = new_record("rid-1", "Email", "credential", _fake_envelope(),
                            _timestamps(updated="2026-08-24T10:00:00+00:00"))
        new_envelope = _fake_envelope()
        new_envelope["ciphertext"] = "11" * 256
        updated = replace_payload(record, new_envelope,
                                  _timestamps(updated="2026-08-24T12:00:00+00:00"))
        # original unchanged
        self.assertEqual(record["payload"]["ciphertext"], "00" * 256)
        # copy carries the new payload and updated timestamp, keeps created_at
        self.assertEqual(updated["payload"]["ciphertext"], "11" * 256)
        self.assertEqual(updated["updated_at"], "2026-08-24T12:00:00+00:00")
        self.assertEqual(updated["created_at"], record["created_at"])

    def test_replace_payload_rejects_non_envelope(self):
        record = new_record("rid-1", "Email", "credential", _fake_envelope(), _timestamps())
        with self.assertRaises(VaultRecordError):
            replace_payload(record, {"not": "envelope"}, _timestamps())


class PublicSummaryTests(unittest.TestCase):
    def test_public_summary_omits_the_sealed_payload(self):
        record = new_record("rid-1", "Email", "credential", _fake_envelope(), _timestamps())
        summary = public_summary(record)
        self.assertNotIn("payload", summary)
        self.assertEqual(summary["record_id"], "rid-1")
        self.assertEqual(summary["kind"], "credential")


if __name__ == "__main__":
    unittest.main()
