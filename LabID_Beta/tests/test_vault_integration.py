import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LABID_ROOT = Path(__file__).resolve().parents[1]

for import_path in (
    str(REPOSITORY_ROOT),
    str(LABID_ROOT),
):
    if import_path not in sys.path:
        sys.path.insert(0, import_path)


from IdentityVault_beta.vault.vault_service import (
    IdentityVaultService,
)
from biometrics.enrollment import enroll_identity
from biometrics.verification import verify_identity
from core.pgm import read_pgm
from samples.sample_generator import generate_samples


class VaultIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_directory = Path.cwd()

        self.temporary_directory = (
            tempfile.TemporaryDirectory()
        )

        os.chdir(self.temporary_directory.name)

        self.vault_path = str(
            Path("test_identity_vault.json")
        )

        self.password = "test-password-one"
        self.new_password = "test-password-two"

        self.service = IdentityVaultService(
            self.vault_path
        )

        self.service.initialize(
            password=self.password
        )

        generate_samples()

    def tearDown(self) -> None:
        os.chdir(self.original_directory)
        self.temporary_directory.cleanup()

    def _enroll(self) -> dict:
        return enroll_identity(
            identity_id="researcher_001",
            display_name="Researcher One",
            image_path="sample_enroll.pgm",
            vault_path=self.vault_path,
            vault_password=self.password,
        )

    def test_encrypted_enrollment_and_verification(
        self,
    ) -> None:
        enrollment = self._enroll()

        identity = enrollment["identity"]

        self.assertEqual(
            identity["storage_mode"],
            "encrypted_identity_vault",
        )

        self.assertFalse(
            Path(
                "data/identities/"
                "researcher_001.json"
            ).exists()
        )

        self.assertFalse(
            Path(
                "data/templates/"
                "researcher_001_template.json"
            ).exists()
        )

        vault_text = Path(
            self.vault_path
        ).read_text(
            encoding="utf-8"
        )

        self.assertNotIn(
            "Researcher One",
            vault_text,
        )

        self.assertNotIn(
            '"intensity_grid"',
            vault_text,
        )

        close_report = verify_identity(
            identity_id="researcher_001",
            image_path="sample_verify_close.pgm",
            vault_path=self.vault_path,
            vault_password=self.password,
        )

        far_report = verify_identity(
            identity_id="researcher_001",
            image_path="sample_verify_far.pgm",
            vault_path=self.vault_path,
            vault_password=self.password,
        )

        self.assertEqual(
            close_report["result"],
            "MATCH",
        )

        self.assertEqual(
            far_report["result"],
            "NO_MATCH",
        )

        self.assertEqual(
            close_report["storage_mode"],
            "encrypted_identity_vault",
        )

        self.assertEqual(
            far_report["storage_mode"],
            "encrypted_identity_vault",
        )

        self.assertIsNone(
            close_report["report_file"]
        )

        self.assertIsNone(
            far_report["report_file"]
        )

        self.assertFalse(
            Path("data/reports").exists()
        )

    def test_wrong_password_is_rejected(
        self,
    ) -> None:
        self._enroll()

        with self.assertRaises(PermissionError):
            verify_identity(
                identity_id="researcher_001",
                image_path="sample_verify_close.pgm",
                vault_path=self.vault_path,
                vault_password="wrong-password",
            )

    def test_ciphertext_modification_is_detected(
        self,
    ) -> None:
        self._enroll()

        vault_file = Path(self.vault_path)

        data = json.loads(
            vault_file.read_text(
                encoding="utf-8"
            )
        )

        first_record = next(
            iter(data["records"].values())
        )

        ciphertext = first_record[
            "encrypted"
        ]["ciphertext"]

        replacement = (
            "A"
            if ciphertext[0] != "A"
            else "B"
        )

        first_record[
            "encrypted"
        ]["ciphertext"] = (
            replacement + ciphertext[1:]
        )

        vault_file.write_text(
            json.dumps(
                data,
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        result = self.service.verify(
            password=self.password
        )

        self.assertEqual(
            result["result"],
            "FAILED",
        )

        self.assertGreater(
            len(result["failed_records"]),
            0,
        )

    def test_password_change_preserves_records(
        self,
    ) -> None:
        self._enroll()

        # Use positional arguments because the current
        # IdentityVaultService uses a different name for
        # the existing-password parameter.
        result = self.service.change_password(
            self.password,
            self.new_password,
        )

        self.assertEqual(
            result["result"],
            "OK",
        )

        self.assertEqual(
            result["record_count"],
            2,
        )

        with self.assertRaises(PermissionError):
            self.service.verify(
                password=self.password
            )

        new_password_verification = (
            self.service.verify(
                password=self.new_password
            )
        )

        self.assertEqual(
            new_password_verification["result"],
            "OK",
        )

        verification = verify_identity(
            identity_id="researcher_001",
            image_path="sample_verify_close.pgm",
            vault_path=self.vault_path,
            vault_password=self.new_password,
        )

        self.assertEqual(
            verification["result"],
            "MATCH",
        )

    def test_binary_pgm_preserves_whitespace_valued_first_pixel(
        self,
    ) -> None:
        image_path = Path(
            "binary_whitespace_pixel.pgm"
        )

        image_path.write_bytes(
            b"P5\n"
            b"2 1\n"
            b"255\n"
            + bytes([10, 200])
        )

        width, height, pixels = read_pgm(
            str(image_path)
        )

        self.assertEqual(
            (width, height),
            (2, 1),
        )

        self.assertEqual(
            pixels,
            [10, 200],
        )


if __name__ == "__main__":
    unittest.main()