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

__version__ = "0.1.0"
__author__ = "Dirk Petersen"
__email__ = "dirk.petersen@protonmail.com"
__license__ = "MIT"

from .core import (
    credentials_need_refresh,
    create_iam_user,
    decrypt_credential,
    encrypt_credential,
    extract_username_prefix,
    generate_usermanager_policy,
    get_aws_account_id,
    get_aws_credentials_path,
    get_current_iam_user,
    get_iam_user_for_access_key,
    get_temp_credentials_for_user,
    get_user_tags,
    is_ssh_key_password_protected,
    read_aws_credentials,
    tag_user,
    update_profile_credentials,
    validate_username_prefix,
    verify_iam_user_exists,
    write_aws_credentials,
)

__all__ = [
    "is_ssh_key_password_protected",
    "encrypt_credential",
    "decrypt_credential",
    "extract_username_prefix",
    "get_aws_credentials_path",
    "read_aws_credentials",
    "write_aws_credentials",
    "create_iam_user",
    "get_iam_user_for_access_key",
    "verify_iam_user_exists",
    "get_temp_credentials_for_user",
    "get_user_tags",
    "tag_user",
    "update_profile_credentials",
    "get_current_iam_user",
    "get_aws_account_id",
    "generate_usermanager_policy",
    "validate_username_prefix",
    "credentials_need_refresh",
]
