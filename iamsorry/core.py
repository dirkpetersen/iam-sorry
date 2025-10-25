"""
Core encryption and credential management functions for iam-sorry.
"""

import base64
import configparser
import os
import struct
import subprocess
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Encryption/Decryption functions for SSH-key based credential encryption
ENCRYPTED_PREFIX = "__encrypted__:"


def get_ssh_key_path():
    """Get the path to the SSH private key."""
    return os.path.expanduser("~/.ssh/id_ed25519")


def is_ssh_key_password_protected(ssh_key_path):
    """
    Detect if an SSH private key is password protected.

    Parses OPENSSH format to check the cipher field:
    - cipher "none" = not encrypted
    - any other cipher = password protected

    Args:
        ssh_key_path: Path to SSH private key

    Returns:
        bool: True if password protected, False if not, None if cannot determine
    """
    try:
        with open(ssh_key_path, "r") as f:
            lines = f.readlines()

        # Extract base64 content between BEGIN and END markers
        key_lines = []
        in_key = False
        for line in lines:
            if "BEGIN" in line:
                in_key = True
                continue
            if "END" in line:
                break
            if in_key:
                key_lines.append(line.strip())

        if not key_lines:
            return None

        # Decode base64
        key_blob = base64.b64decode("".join(key_lines))

        # Parse OPENSSH format
        # Magic: "openssh-key-v1\0" (15 bytes)
        if key_blob[:15] == b"openssh-key-v1\0":
            # Skip magic (15 bytes)
            pos = 15

            # Read cipher name length (4 bytes, big-endian)
            if pos + 4 > len(key_blob):
                return None  # Invalid format
            cipher_len = struct.unpack(">I", key_blob[pos : pos + 4])[0]
            pos += 4

            # Validate cipher_len to prevent buffer overflow
            if cipher_len > len(key_blob) - pos or cipher_len > 1024:
                return None  # Invalid or suspiciously large cipher length

            # Read cipher name
            cipher_name = key_blob[pos : pos + cipher_len].decode()

            # If cipher is "none", key is NOT encrypted
            return cipher_name != "none"

        return None

    except Exception:
        return None


def derive_encryption_key_from_ssh_key(ssh_key_path):
    """
    Derive an AES-256 encryption key from SSH private key using HKDF.

    Args:
        ssh_key_path: Path to SSH private key

    Returns:
        bytes: 32-byte encryption key

    Raises:
        Exception: If SSH key cannot be read
    """
    try:
        with open(ssh_key_path, "rb") as f:
            ssh_key_data = f.read()

        # Use HKDF to derive a 256-bit key from the SSH key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"iam-sorry-encryption",
            backend=default_backend(),
        )
        encryption_key = hkdf.derive(ssh_key_data)
        return encryption_key
    except FileNotFoundError:
        raise Exception(
            f"SSH key not found at {ssh_key_path}\n"
            f"  To fix: Generate an ED25519 key with: ssh-keygen -t ed25519 -f {ssh_key_path}\n"
            f"  Or update get_ssh_key_path() to point to your existing key"
        )
    except PermissionError:
        raise Exception(
            f"Permission denied reading SSH key at {ssh_key_path}\n"
            f"  To fix: chmod 600 {ssh_key_path}"
        )
    except Exception as e:
        raise Exception(
            f"Failed to derive encryption key from SSH key: {e}\n"
            f"  SSH key path: {ssh_key_path}\n"
            f"  Ensure the key is a valid OPENSSH format private key"
        )


def encrypt_credential(value, ssh_key_path):
    """
    Encrypt a credential value using SSH-key derived encryption.

    Args:
        value: The credential value to encrypt (string)
        ssh_key_path: Path to SSH private key

    Returns:
        str: Encrypted value with prefix (format: __encrypted__:<base64-encoded-ciphertext>)

    Raises:
        Exception: If SSH key is not password protected
    """
    try:
        # Validate that the SSH key is password protected
        is_protected = is_ssh_key_password_protected(ssh_key_path)

        if is_protected is False:
            raise Exception(
                f"SSH key '{ssh_key_path}' is not password protected. "
                f"For security, only password-protected SSH keys can be used for encryption. "
                f"Add a passphrase: ssh-keygen -p -f {ssh_key_path}"
            )
        elif is_protected is None:
            raise Exception(
                f"Could not verify if SSH key '{ssh_key_path}' is password protected. "
                f"Please ensure it's a valid OPENSSH format key."
            )

        encryption_key = derive_encryption_key_from_ssh_key(ssh_key_path)

        # Generate random nonce (96 bits for AESGCM)
        nonce = os.urandom(12)

        # Encrypt the credential value
        cipher = AESGCM(encryption_key)
        ciphertext = cipher.encrypt(nonce, value.encode(), None)

        # Combine nonce + ciphertext and encode to base64
        encrypted_data = nonce + ciphertext
        encoded = base64.b64encode(encrypted_data).decode()

        return f"{ENCRYPTED_PREFIX}{encoded}"
    except Exception as e:
        print(f"Error: Failed to encrypt credential: {e}", file=sys.stderr)
        sys.exit(1)


def decrypt_credential(encrypted_value, ssh_key_path):
    """
    Decrypt a credential value encrypted with SSH key.

    Args:
        encrypted_value: The encrypted credential value (with __encrypted__: prefix)
        ssh_key_path: Path to SSH private key

    Returns:
        str: Decrypted credential value
    """
    try:
        if not encrypted_value.startswith(ENCRYPTED_PREFIX):
            return encrypted_value  # Not encrypted, return as-is

        # Remove prefix and decode from base64
        encoded_data = encrypted_value[len(ENCRYPTED_PREFIX) :]
        try:
            encrypted_data = base64.b64decode(encoded_data)
        except Exception as e:
            raise Exception(
                f"Corrupted encrypted data (invalid base64 encoding)\n"
                f"  The encrypted credential appears to be corrupted or manually edited.\n"
                f"  You may need to re-encrypt with: iam-sorry --profile <profile> --encrypt"
            )

        # Validate minimum length (12 bytes nonce + at least 1 byte ciphertext + 16 bytes auth tag)
        if len(encrypted_data) < 29:
            raise Exception(
                f"Invalid encrypted data: too short ({len(encrypted_data)} bytes, expected at least 29)\n"
                f"  The encrypted credential appears to be corrupted.\n"
                f"  You may need to re-encrypt with: iam-sorry --profile <profile> --encrypt"
            )

        # Split nonce (first 12 bytes) and ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # Derive the encryption key
        encryption_key = derive_encryption_key_from_ssh_key(ssh_key_path)

        # Decrypt
        cipher = AESGCM(encryption_key)
        try:
            plaintext = cipher.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise Exception(
                f"Decryption failed (authentication tag mismatch or wrong key)\n"
                f"  Possible causes:\n"
                f"    - SSH key at {ssh_key_path} is not the same key used for encryption\n"
                f"    - Encrypted data has been tampered with or corrupted\n"
                f"    - SSH key passphrase was changed after encryption\n"
                f"  To fix:\n"
                f"    - Ensure ssh-agent has loaded the correct key: ssh-add {ssh_key_path}\n"
                f"    - Re-encrypt with current SSH key: iam-sorry --profile <profile> --encrypt"
            )

        return plaintext.decode()
    except Exception as e:
        print(f"Error: Failed to decrypt credential", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        sys.exit(1)


def is_encrypted_credential(value):
    """Check if a credential value is encrypted."""
    return isinstance(value, str) and value.startswith(ENCRYPTED_PREFIX)


def decrypt_profile_credentials(config, profile_name, ssh_key_path):
    """
    Decrypt encrypted credentials in a profile if needed.

    Args:
        config: ConfigParser object with credentials
        profile_name: Name of the profile
        ssh_key_path: Path to SSH private key
    """
    if profile_name not in config:
        return

    profile = config[profile_name]

    # Decrypt access key if encrypted
    if "aws_access_key_id" in profile and is_encrypted_credential(profile["aws_access_key_id"]):
        profile["aws_access_key_id"] = decrypt_credential(
            profile["aws_access_key_id"], ssh_key_path
        )

    # Decrypt secret key if encrypted
    if "aws_secret_access_key" in profile and is_encrypted_credential(
        profile["aws_secret_access_key"]
    ):
        profile["aws_secret_access_key"] = decrypt_credential(
            profile["aws_secret_access_key"], ssh_key_path
        )


def get_aws_credentials_path():
    """Get the AWS credentials file path."""
    aws_creds = os.path.expanduser("~/.aws/credentials")
    return aws_creds


def get_aws_config_path():
    """Get the AWS config file path."""
    aws_config = os.path.expanduser("~/.aws/config")
    return aws_config


def get_current_iam_user(profile_name):
    """
    Get the current IAM username using STS GetCallerIdentity.

    Args:
        profile_name: AWS profile to use

    Returns:
        str: IAM username

    Raises:
        Exception: If unable to determine current user or if using non-user credentials
    """
    try:
        session = create_session_with_profile(profile_name)
        sts_client = session.client("sts")
        response = sts_client.get_caller_identity()
        arn = response["Arn"]

        # Handle different ARN types
        # IAM User: arn:aws:iam::ACCOUNT_ID:user/USERNAME
        if ":user/" in arn:
            username = arn.split(":user/")[1]
            return username

        # Assumed Role: arn:aws:sts::ACCOUNT_ID:assumed-role/ROLE_NAME/SESSION_NAME
        if ":assumed-role/" in arn:
            raise Exception(
                f"Profile '{profile_name}' is using an assumed role, not an IAM user. "
                f"iam-sorry requires IAM user credentials with permanent access keys. "
                f"ARN: {arn}"
            )

        # Federated User: arn:aws:sts::ACCOUNT_ID:federated-user/USERNAME
        if ":federated-user/" in arn:
            raise Exception(
                f"Profile '{profile_name}' is using federated credentials, not an IAM user. "
                f"iam-sorry requires IAM user credentials with permanent access keys. "
                f"ARN: {arn}"
            )

        # Root Account: arn:aws:iam::ACCOUNT_ID:root
        if ":root" in arn:
            raise Exception(
                f"Profile '{profile_name}' is using root account credentials. "
                f"For security, iam-sorry should only be used with IAM user credentials, not root. "
                f"ARN: {arn}"
            )

        # Unknown ARN format
        raise Exception(
            f"Profile '{profile_name}' has an unrecognized ARN format. "
            f"iam-sorry requires IAM user credentials. "
            f"ARN: {arn}"
        )

    except Exception as e:
        print(f"Error: Failed to get current IAM user", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        sys.exit(1)


def extract_username_prefix(username):
    """
    Extract the prefix from a username (everything before the first hyphen).

    Examples:
        dirk-admin → dirk
        alice-manager → alice
        bob → bob
        dirk-team-admin → dirk

    Args:
        username: IAM username

    Returns:
        str: Username prefix
    """
    if "-" in username:
        return username.split("-")[0]
    return username


def validate_username_prefix(manager_username, target_username):
    """
    Validate that the target username matches the manager's prefix.

    Manager can only create/manage users that:
    - Start with {prefix}- (e.g., dirk-admin can manage dirk-bedrock)
    - OR are exactly the prefix (e.g., dirk-admin can manage dirk)
    - BUT not themselves if they are exactly the prefix (dirk cannot create dirk)

    Args:
        manager_username: Username of the manager (e.g., dirk-admin)
        target_username: Username to be created/managed (e.g., dirk-bedrock)

    Returns:
        tuple: (is_valid: bool, reason: str)
    """
    # Validate usernames are not empty or whitespace-only
    if not manager_username or not manager_username.strip():
        return (False, "Manager username cannot be empty or whitespace-only")

    if not target_username or not target_username.strip():
        return (False, "Target username cannot be empty or whitespace-only")

    manager_prefix = extract_username_prefix(manager_username)
    target_prefix = extract_username_prefix(target_username)

    # Check if target username starts with manager's prefix
    if target_username == manager_prefix:
        # Allow managing user with exact prefix name (e.g., dirk-admin can manage dirk)
        # But prevent manager from creating themselves
        if manager_username == target_username:
            return (
                False,
                f"Cannot manage your own user account '{manager_username}'",
            )
        return (True, "Managing user with exact prefix")

    # Check if target starts with prefix followed by hyphen
    if target_username.startswith(f"{manager_prefix}-"):
        return (True, f"Target username starts with required prefix '{manager_prefix}-'")

    # Validation failed
    return (
        False,
        f"Username '{target_username}' does not match required prefix. "
        f"Manager '{manager_username}' (prefix: '{manager_prefix}') can only manage users "
        f"named '{manager_prefix}' or '{manager_prefix}-*'",
    )


def get_aws_account_id(profile_name):
    """
    Get the AWS account ID using STS GetCallerIdentity.

    Args:
        profile_name: AWS profile to use

    Returns:
        str: AWS account ID

    Raises:
        Exception: If unable to determine account ID
    """
    try:
        session = create_session_with_profile(profile_name)
        sts_client = session.client("sts")
        response = sts_client.get_caller_identity()
        return response["Account"]
    except Exception as e:
        print(f"Error: Failed to get AWS account ID", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        sys.exit(1)


def generate_usermanager_policy(profile_name, user_prefix=None):
    """
    Generate a least-privilege IAM policy for the current user to act as usermanager.

    This policy enforces username prefix matching:
    - Manager "dirk-admin" can only manage users starting with "dirk-" or exactly "dirk"
    - Manager "alice" can only manage users starting with "alice-"
    - Prefix is everything before the first hyphen (or entire username if no hyphen)

    Tagging Strategy:
    - Manager can TAG users to add restrictions (one-time setup)
    - Manager CANNOT untag users (prevents removing restrictions)
    - This ensures restrictions cannot be bypassed after being set

    Args:
        profile_name: AWS profile to use for lookups
        user_prefix: Optional explicit prefix to use. If None, uses prefix from current IAM user

    Returns:
        dict: IAM policy document
    """
    import json

    account_id = get_aws_account_id(profile_name)

    # If user_prefix not specified, extract from current IAM user
    if user_prefix is None:
        current_user = get_current_iam_user(profile_name)
        prefix = extract_username_prefix(current_user)
    else:
        prefix = user_prefix

    # Build resource patterns: {prefix} and {prefix}-*
    # Example: if prefix is "dirk", allow "dirk" and "dirk-*"
    user_resources = [
        f"arn:aws:iam::{account_id}:user/{prefix}",
        f"arn:aws:iam::{account_id}:user/{prefix}-*",
    ]

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CreateUsers",
                "Effect": "Allow",
                "Action": ["iam:CreateUser"],
                "Resource": user_resources,
            },
            {
                "Sid": "ManageUserCredentials",
                "Effect": "Allow",
                "Action": [
                    "iam:CreateAccessKey",
                    "iam:DeleteAccessKey",
                    "iam:UpdateAccessKey",
                    "iam:ListAccessKeys",
                    "iam:GetAccessKeyLastUsed",
                ],
                "Resource": user_resources,
            },
            {
                "Sid": "ListUsersForLookup",
                "Effect": "Allow",
                "Action": ["iam:ListUsers", "iam:ListAccessKeys", "iam:GetUser"],
                "Resource": "*",
            },
            {
                "Sid": "STSGetSessionToken",
                "Effect": "Allow",
                "Action": ["sts:GetSessionToken"],
                "Resource": "*",
            },
            {
                "Sid": "ManageRestrictionTags",
                "Effect": "Allow",
                "Action": [
                    "iam:TagUser",
                    "iam:ListUserTags",
                ],
                "Resource": user_resources,
            },
            {
                "Sid": "PreventTagRemovalOrModification",
                "Effect": "Deny",
                "Action": ["iam:UntagUser"],
                "Resource": user_resources,
            },
        ],
    }

    return policy


def read_aws_credentials(creds_file, auto_decrypt=False):
    """
    Read AWS credentials file.

    Args:
        creds_file: Path to credentials file
        auto_decrypt: If True, automatically decrypt encrypted credentials

    Returns:
        ConfigParser object with credentials
    """
    config = configparser.ConfigParser()
    # Preserve case sensitivity for AWS credentials
    config.optionxform = str
    if os.path.exists(creds_file):
        config.read(creds_file)

    # Auto-decrypt all profiles if requested
    if auto_decrypt:
        ssh_key_path = get_ssh_key_path()
        for section in config.sections():
            decrypt_profile_credentials(config, section, ssh_key_path)

    return config


def write_aws_credentials(creds_file, config):
    """Write AWS credentials file with secure permissions."""
    Path(creds_file).parent.mkdir(parents=True, exist_ok=True)

    # Use os.open() with O_CREAT to atomically create file with secure permissions
    # This prevents race condition where file is created with default permissions
    # then chmod'd later (exposing credentials briefly)
    fd = os.open(creds_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            config.write(f)
    except:
        # If write fails, close fd to prevent leak
        os.close(fd)
        raise


def create_session_with_profile(profile_name):
    """
    Create a boto3 session with credentials from a profile, auto-decrypting if needed.

    Args:
        profile_name: AWS profile name

    Returns:
        boto3.Session configured with the profile's credentials

    Raises:
        Exception: If profile not found or credentials invalid
    """
    creds_file = get_aws_credentials_path()
    config = read_aws_credentials(creds_file, auto_decrypt=True)

    if profile_name not in config:
        raise Exception(f"Profile '{profile_name}' not found")

    profile = config[profile_name]
    access_key = profile.get("aws_access_key_id")
    secret_key = profile.get("aws_secret_access_key")
    session_token = profile.get("aws_session_token")

    if not access_key or not secret_key:
        raise Exception(f"Profile '{profile_name}' missing credentials")

    # Create session with explicit credentials (bypasses AWS credentials file)
    return boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token if session_token else None,
    )


def get_iam_user_for_access_key(profile_name, access_key_id):
    """
    Get the IAM username associated with an access key.

    Args:
        profile_name: AWS profile to use for the IAM call
        access_key_id: The access key ID to look up

    Returns:
        IAM username or None if not found
    """
    try:
        session = create_session_with_profile(profile_name)
        iam_client = session.client("iam")

        # List all IAM users and find the one with this access key
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                # Get access keys for this user
                keys_response = iam_client.list_access_keys(UserName=username)
                for key in keys_response["AccessKeyMetadata"]:
                    if key["AccessKeyId"] == access_key_id:
                        return username

        return None
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return None
        error_code = e.response["Error"]["Code"]
        if error_code == "InvalidClientTokenId":
            print(
                f"Error: Manager profile '{profile_name}' has invalid credentials",
                file=sys.stderr,
            )
            print(
                f"\nThe '{profile_name}' profile credentials are not valid or have expired.",
                file=sys.stderr,
            )
            print(f"Please check your ~/.aws/credentials file.", file=sys.stderr)
        else:
            print(f"Error: Failed to look up IAM user", file=sys.stderr)
            print(f"Details: {e}", file=sys.stderr)
        sys.exit(1)
    except BotoCoreError as e:
        print(f"Error: AWS connection failed", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        sys.exit(1)


def verify_iam_user_exists(profile_name, username):
    """
    Verify that an IAM user exists.

    Args:
        profile_name: AWS profile to use for the IAM call
        username: The username to verify

    Returns:
        True if user exists, False otherwise
    """
    try:
        session = create_session_with_profile(profile_name)
        iam_client = session.client("iam")
        iam_client.get_user(UserName=username)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return False
        error_code = e.response["Error"]["Code"]
        if error_code == "InvalidClientTokenId":
            print(
                f"Error: Manager profile '{profile_name}' has invalid credentials",
                file=sys.stderr,
            )
            print(
                f"\nThe '{profile_name}' profile credentials are not valid or have expired.",
                file=sys.stderr,
            )
            print(f"Please check your ~/.aws/credentials file.", file=sys.stderr)
        else:
            print(f"Error: Failed to check if user '{username}' exists", file=sys.stderr)
            print(f"Details: {e}", file=sys.stderr)
        sys.exit(1)


def create_iam_user(profile_name, username):
    """
    Create a new IAM user.

    Args:
        profile_name: AWS profile to use
        username: IAM username to create

    Returns:
        dict: User information

    Raises:
        Exception: If user creation fails
    """
    try:
        session = create_session_with_profile(profile_name)
        iam_client = session.client("iam")
        response = iam_client.create_user(UserName=username)
        return response["User"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "EntityAlreadyExists":
            return None  # User already exists
        raise Exception(f"Failed to create IAM user '{username}': {e}")


def get_user_tags(profile_name, username):
    """
    Get tags for an IAM user.

    Args:
        profile_name: AWS profile to use
        username: IAM username

    Returns:
        dict: Tags as key-value pairs, or empty dict if no tags
    """
    try:
        session = create_session_with_profile(profile_name)
        iam_client = session.client("iam")
        response = iam_client.list_user_tags(UserName=username)
        tags = {}
        for tag in response.get("Tags", []):
            tags[tag["Key"]] = tag["Value"]
        return tags
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return {}
        raise


def tag_user(profile_name, username, tags_dict):
    """
    Add tags to an IAM user.

    Args:
        profile_name: AWS profile to use
        username: IAM username
        tags_dict: Dictionary of tags to apply {key: value}

    Raises:
        Exception: If tagging fails
    """
    try:
        session = create_session_with_profile(profile_name)
        iam_client = session.client("iam")

        tags_list = [{"Key": k, "Value": v} for k, v in tags_dict.items()]
        iam_client.tag_user(UserName=username, Tags=tags_list)
    except ClientError as e:
        raise Exception(f"Failed to tag user '{username}': {e}")


def get_temp_credentials_for_user(manager_profile, username, duration_seconds=43200):
    """
    Get temporary credentials for an IAM user using GetSessionToken.

    Args:
        manager_profile: AWS profile to use for making the call
        username: IAM username to get credentials for (informational)
        duration_seconds: How long credentials should be valid (default: 12 hours)

    Returns:
        dict with AccessKeyId, SecretAccessKey, SessionToken, Expiration
    """
    try:
        session = create_session_with_profile(manager_profile)
        sts_client = session.client("sts")

        # Use GetSessionToken to get temporary credentials
        response = sts_client.get_session_token(DurationSeconds=duration_seconds)

        credentials = response["Credentials"]
        return {
            "AccessKeyId": credentials["AccessKeyId"],
            "SecretAccessKey": credentials["SecretAccessKey"],
            "SessionToken": credentials["SessionToken"],
            "Expiration": credentials["Expiration"].isoformat(),
        }
    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "InvalidClientTokenId":
            print(
                f"Error: Manager profile '{manager_profile}' has invalid credentials",
                file=sys.stderr,
            )
            print(
                f"\nThe '{manager_profile}' profile credentials are not valid or have expired.",
                file=sys.stderr,
            )
            print(f"Please check your ~/.aws/credentials file.", file=sys.stderr)
        else:
            print(
                f"Error: Failed to get temporary credentials for user '{username}'",
                file=sys.stderr,
            )
            print(f"Details: {e}", file=sys.stderr)
        sys.exit(1)
    except BotoCoreError as e:
        print(f"Error: AWS connection failed", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        sys.exit(1)


def credentials_need_refresh(profile, threshold_minutes=5):
    """
    Check if credentials need to be refreshed.

    Args:
        profile: ConfigParser section with credentials
        threshold_minutes: Refresh if expiring within this many minutes (default: 5)

    Returns:
        tuple: (needs_refresh: bool, reason: str)
    """
    from datetime import datetime, timedelta, timezone

    # Permanent credentials don't need refresh
    if "aws_session_token" not in profile or not profile["aws_session_token"]:
        return False, "permanent credentials"

    # Check if we have expiration timestamp
    if "expiration" not in profile:
        return False, "no expiration timestamp"

    try:
        # Parse expiration timestamp (ISO format)
        expiration_str = profile["expiration"]
        # Handle both with and without timezone
        if expiration_str.endswith("Z"):
            expiration = datetime.fromisoformat(expiration_str.replace("Z", "+00:00"))
        elif "+" in expiration_str or expiration_str.count("-") > 2:
            expiration = datetime.fromisoformat(expiration_str)
        else:
            # No timezone info, assume UTC
            expiration = datetime.fromisoformat(expiration_str).replace(tzinfo=timezone.utc)

        # Get current time in UTC
        now = datetime.now(timezone.utc)

        # Check if expired or expiring soon
        time_remaining = expiration - now

        if time_remaining.total_seconds() < 0:
            return True, "credentials expired"
        elif time_remaining.total_seconds() < (threshold_minutes * 60):
            minutes_left = int(time_remaining.total_seconds() / 60)
            return True, f"credentials expiring in {minutes_left} minutes"
        else:
            return False, "credentials still valid"

    except Exception as e:
        # If we can't parse expiration, don't refresh
        return False, f"could not parse expiration: {e}"


def update_profile_credentials(profile_name, credentials, iam_username=None, encrypt=False):
    """
    Update a profile in the AWS credentials file with new temporary credentials.

    Args:
        profile_name: Name of the profile to update
        credentials: Dict with AccessKeyId, SecretAccessKey, SessionToken
        iam_username: IAM username associated with credentials
        encrypt: If True, encrypt the access key and secret key
    """
    creds_file = get_aws_credentials_path()
    config = read_aws_credentials(creds_file)

    # Ensure profile section exists
    if profile_name not in config:
        config[profile_name] = {}

    # Get values to store
    access_key = credentials["AccessKeyId"]
    secret_key = credentials["SecretAccessKey"]

    # Encrypt if requested
    if encrypt:
        ssh_key_path = get_ssh_key_path()
        access_key = encrypt_credential(access_key, ssh_key_path)
        secret_key = encrypt_credential(secret_key, ssh_key_path)

    # Update credentials
    config[profile_name]["aws_access_key_id"] = access_key
    config[profile_name]["aws_secret_access_key"] = secret_key
    config[profile_name]["aws_session_token"] = credentials["SessionToken"]

    # Store the IAM username so we can identify it later even with temporary credentials
    if iam_username:
        config[profile_name]["credentials_owner"] = iam_username

    # Store expiration timestamp if available (for auto-refresh)
    if "Expiration" in credentials:
        config[profile_name]["expiration"] = credentials["Expiration"]

    write_aws_credentials(creds_file, config)

    # Also update ~/.aws/config with region if this is a new profile
    config_file = get_aws_config_path()
    config_parser = configparser.ConfigParser()
    config_parser.optionxform = str  # Preserve case sensitivity
    if os.path.exists(config_file):
        config_parser.read(config_file)

    # Determine profile section name: "default" for default profile, "profile NAME" for others
    profile_section = "default" if profile_name == "default" else f"profile {profile_name}"

    # Only update config if profile doesn't exist yet (avoid overwriting user settings)
    if profile_section not in config_parser:
        config_parser[profile_section] = {}

        # Get current region from iam-sorry profile in ~/.aws/config
        region = "us-east-1"  # Default fallback
        try:
            config_reader = configparser.ConfigParser()
            config_reader.read(config_file)
            # Look for region in iam-sorry profile
            iam_sorry_section = "profile iam-sorry"
            if iam_sorry_section in config_reader:
                region = config_reader[iam_sorry_section].get("region", "us-east-1")
            elif "iam-sorry" in config_reader:
                region = config_reader["iam-sorry"].get("region", "us-east-1")
        except:
            pass  # Use default if anything fails

        config_parser[profile_section]["region"] = region

        # Write config file with secure permissions
        Path(config_file).parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, "w") as f:
            config_parser.write(f)
        os.chmod(config_file, 0o644)  # Config file can be world-readable

        # Print the region that was set
        print(f"✓ Region: {region}", file=sys.stderr)
