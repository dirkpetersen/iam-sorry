"""
iam-sorry: AWS Credentials Manager - Pull temporary credentials for an IAM user.

A Python CLI utility that manages temporary AWS credentials for IAM users with
optional SSH-key based encryption. It integrates with AWS IAM and STS to fetch
short-lived session tokens, encrypt them optionally, and update local AWS
credential profiles with full security controls.

Key features:
- Generate temporary AWS credentials for any IAM user
- Optional SSH-key based encryption for credentials
- Batch operations support via environment injection
- SSH key-based credential encryption at rest
"""

__version__ = "0.2.0"
__author__ = "Dirk Petersen"
__email__ = "dirk.petersen@protonmail.com"
__license__ = "MIT"

from .core import (
    create_access_key_for_user,
    create_iam_user,
    create_session_with_profile,
    credentials_need_refresh,
    decrypt_credential,
    encrypt_credential,
    extract_username_prefix,
    generate_usermanager_policy,
    get_aws_account_id,
    get_aws_config_path,
    get_aws_credentials_path,
    get_current_iam_user,
    get_iam_user_for_access_key,
    get_temp_credentials_for_user,
    get_user_tags,
    is_ssh_key_password_protected,
    put_user_policy,
    read_aws_credentials,
    tag_user,
    update_profile_credentials,
    validate_username_prefix,
    verify_iam_user_exists,
    write_aws_credentials,
)

__all__ = [
    # Python API - Most commonly used for programmatic access
    "create_session_with_profile",
    "read_aws_credentials",
    "get_aws_credentials_path",
    "credentials_need_refresh",
    # Encryption utilities
    "is_ssh_key_password_protected",
    "encrypt_credential",
    "decrypt_credential",
    # Credential management
    "get_temp_credentials_for_user",
    "update_profile_credentials",
    # IAM user operations
    "create_iam_user",
    "verify_iam_user_exists",
    "get_current_iam_user",
    "get_iam_user_for_access_key",
    # IAM policy operations
    "generate_usermanager_policy",
    "put_user_policy",
    "create_access_key_for_user",
    # User tagging
    "get_user_tags",
    "tag_user",
    # Username utilities
    "extract_username_prefix",
    "validate_username_prefix",
    # AWS utilities
    "get_aws_account_id",
    "get_aws_config_path",
    # File operations
    "write_aws_credentials",
]
