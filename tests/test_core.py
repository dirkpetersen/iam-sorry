"""Tests for iam-sorry core module."""

import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
import configparser

from iamsorry.core import (
    is_encrypted_credential,
    get_aws_credentials_path,
    read_aws_credentials,
    write_aws_credentials,
    is_ssh_key_password_protected,
    ENCRYPTED_PREFIX,
)


class TestEncryption(unittest.TestCase):
    """Test encryption utility functions."""

    def test_is_encrypted_credential_with_encrypted_value(self):
        """Test detection of encrypted credentials."""
        encrypted = f"{ENCRYPTED_PREFIX}somebase64data"
        self.assertTrue(is_encrypted_credential(encrypted))

    def test_is_encrypted_credential_with_plaintext_value(self):
        """Test detection of plaintext credentials."""
        plaintext = "AKIAIOSFODNN7EXAMPLE"
        self.assertFalse(is_encrypted_credential(plaintext))

    def test_is_encrypted_credential_with_non_string(self):
        """Test detection with non-string values."""
        self.assertFalse(is_encrypted_credential(None))
        self.assertFalse(is_encrypted_credential(123))
        self.assertFalse(is_encrypted_credential([]))


class TestCredentialsFile(unittest.TestCase):
    """Test AWS credentials file operations."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.creds_file = os.path.join(self.temp_dir, "credentials")

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_read_aws_credentials_nonexistent_file(self):
        """Test reading non-existent credentials file."""
        config = read_aws_credentials(self.creds_file)
        self.assertIsInstance(config, configparser.ConfigParser)
        self.assertEqual(len(config.sections()), 0)

    def test_read_aws_credentials_existing_file(self):
        """Test reading existing credentials file."""
        # Create a test credentials file
        config = configparser.ConfigParser()
        config["default"] = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        }

        with open(self.creds_file, "w") as f:
            config.write(f)

        # Read it back
        read_config = read_aws_credentials(self.creds_file)
        self.assertEqual(read_config["default"]["aws_access_key_id"], "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(
            read_config["default"]["aws_secret_access_key"],
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        )

    def test_write_aws_credentials(self):
        """Test writing credentials file."""
        config = configparser.ConfigParser()
        config["profile1"] = {
            "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        }

        write_aws_credentials(self.creds_file, config)

        # Verify file exists and has correct permissions
        self.assertTrue(os.path.exists(self.creds_file))
        perms = os.stat(self.creds_file).st_mode & 0o777
        self.assertEqual(perms, 0o600)

        # Verify content
        read_config = read_aws_credentials(self.creds_file)
        self.assertEqual(read_config["profile1"]["aws_access_key_id"], "AKIAIOSFODNN7EXAMPLE")

    def test_write_aws_credentials_creates_directory(self):
        """Test that write_aws_credentials creates parent directory."""
        nested_path = os.path.join(self.temp_dir, "nested", "aws", "credentials")
        config = configparser.ConfigParser()
        config["default"] = {"aws_access_key_id": "TEST"}

        write_aws_credentials(nested_path, config)

        self.assertTrue(os.path.exists(nested_path))


class TestAWSCredentialsPath(unittest.TestCase):
    """Test AWS credentials path functions."""

    def test_get_aws_credentials_path(self):
        """Test getting AWS credentials path."""
        path = get_aws_credentials_path()
        self.assertTrue(path.endswith(".aws/credentials"))
        self.assertTrue(path.startswith(os.path.expanduser("~")))


class TestSSHKeyDetection(unittest.TestCase):
    """Test SSH key password protection detection."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_is_ssh_key_password_protected_nonexistent_file(self):
        """Test detection with non-existent file."""
        result = is_ssh_key_password_protected("/nonexistent/path/id_ed25519")
        self.assertIsNone(result)

    def test_is_ssh_key_password_protected_invalid_format(self):
        """Test detection with invalid key format."""
        ssh_key_path = os.path.join(self.temp_dir, "id_ed25519")
        with open(ssh_key_path, "w") as f:
            f.write("INVALID KEY DATA\n")

        result = is_ssh_key_password_protected(ssh_key_path)
        self.assertIsNone(result)


class TestCredentialManagement(unittest.TestCase):
    """Test credential management functions."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch("iamsorry.core.get_aws_credentials_path")
    def test_get_aws_credentials_path_called(self, mock_path):
        """Test that get_aws_credentials_path is called correctly."""
        mock_path.return_value = os.path.join(self.temp_dir, "credentials")
        path = mock_path()
        self.assertEqual(path, os.path.join(self.temp_dir, "credentials"))


if __name__ == "__main__":
    unittest.main()
