"""
Command-line interface for iam-sorry.
"""

import argparse
import json
import os
import sys

from .core import (
    credentials_need_refresh,
    create_iam_user,
    encrypt_credential,
    generate_usermanager_policy,
    get_aws_account_id,
    get_aws_config_path,
    get_aws_credentials_path,
    get_current_iam_user,
    get_iam_user_for_access_key,
    get_ssh_key_path,
    get_temp_credentials_for_user,
    get_user_tags,
    read_aws_credentials,
    tag_user,
    update_profile_credentials,
    validate_username_prefix,
    verify_iam_user_exists,
    write_aws_credentials,
)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Pull temporary AWS credentials for an IAM user and update a profile",
        epilog="Examples:\n"
        "  AWS_PROFILE=usermanager iam-sorry admin\n"
        "  iam-sorry --profile usermanager admin\n"
        "  AWS_PROFILE=usermanager iam-sorry  (refresh iam-sorry profile)\n"
        "  iam-sorry --profile usermanager --print-policy  (show personalized IAM policy)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--profile",
        default=None,
        help="AWS profile to use for credential management (defaults to 'iam-sorry', overridden by AWS_PROFILE env var, then by this argument)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=36,
        help="Duration in hours for temporary credentials (default: 36, max: 36)",
    )
    parser.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt the iam-sorry profile permanent credentials at rest using SSH key (one-time setup). "
        "Only applies when updating the iam-sorry profile itself, not temporary credentials",
    )
    parser.add_argument(
        "--eval",
        metavar="PROFILE",
        nargs="?",
        const="",  # Empty string when --eval is used without argument
        default=None,  # None when --eval is not used at all
        help="Output shell export statements for a profile's credentials (for eval in shell scripts). "
        "To view decrypted credentials, use: iam-sorry --eval iam-sorry",
    )
    parser.add_argument(
        "--print-policy",
        metavar="[USER_PREFIX]",
        nargs="?",
        const="",  # Empty string when --print-policy is used without argument
        default=None,  # None when --print-policy is not used at all
        help="Print the recommended IAM policy. If USER_PREFIX is omitted, uses current Unix shell username as prefix. "
        "If specified, uses that prefix (e.g., --print-policy iam)",
    )
    parser.add_argument(
        "--chown",
        metavar="OWNER",
        help="Delegate user management to another user (managers only). Creates user outside namespace (one-time only). "
        "Usage: ./iam-sorry --profile iam-sorry jimmy-bedrock --chown jimmy",
    )
    parser.add_argument(
        "profile_to_manage",
        nargs="?",
        default=None,
        help="Profile name to update. If profile exists, uses its access key to determine IAM user. "
        "If not, treats it as an IAM username. If omitted, defaults to the management profile (iam-sorry by default).",
    )

    args = parser.parse_args()

    # Handle --print-policy flag
    if args.print_policy is not None:
        import pwd

        # Determine which profile to use for getting user/account info
        # Default to iam-sorry if not specified
        manager_profile = args.profile or os.environ.get("AWS_PROFILE") or "iam-sorry"

        # Determine user prefix for policy
        if args.print_policy == "":
            # --print-policy was specified without an argument
            # Use the current Unix shell username as the prefix
            try:
                unix_username = pwd.getpwuid(os.getuid()).pw_name
                user_prefix = unix_username
            except:
                print(
                    "Error: Could not determine current Unix username",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            # --print-policy was specified with an argument
            user_prefix = args.print_policy

        try:
            account_id = get_aws_account_id(manager_profile)
            policy = generate_usermanager_policy(manager_profile, user_prefix)

            # Print with nice formatting
            print(f"# IAM Policy for manager with prefix: {user_prefix}")
            print(f"# Account: {account_id}")
            print(f"# Generated for: {user_prefix}-mgr or similar")
            print()
            print(json.dumps(policy, indent=2))

            # Print instructions
            print()
            print("# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print("# INSTRUCTIONS FOR AWS ADMINISTRATOR")
            print("# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print()
            print("# 1. Send this policy to your AWS administrator")
            print(f"#    Administrator should create a highly restricted IAM user (e.g., '{user_prefix}-mgr')")
            print(f"#    who can create other users with prefix '{user_prefix}' and refresh their credentials")
            print()
            print("# 2. After the user is created, the administrator should:")
            print("#    a) Log in to AWS Console")
            print(f"#    b) Go to: IAM → Users → {user_prefix}-mgr")
            print("#    c) Click: 'Add Permissions' → 'Create Inline Policy'")
            print("#    d) Select tab: 'JSON'")
            print("#    e) Clear the default policy and paste the JSON policy above")
            print("#    f) Click: 'Review Policy' → 'Put Inline Policy'")
            print()
            print("# 3. Provide the new IAM user with:")
            print("#    - AWS Access Key ID")
            print("#    - AWS Secret Access Key")
            print("#    - AWS Console URL (if needed)")
            print()
            print("# 4. The user can then configure their AWS credentials:")
            print(f"#    $ aws configure --profile iam-sorry")
            print("#    Then use this tool to create and manage their namespace users")
            print()
            sys.exit(0)
        except Exception as e:
            print(f"Error: Failed to generate policy: {e}", file=sys.stderr)
            sys.exit(1)


    # Handle --eval flag to output shell export statements
    if args.eval is not None:
        # If --eval has no argument (empty string), default to 'default' profile (not iam-sorry)
        # The iam-sorry profile is only for management operations, not for eval
        if args.eval == "":
            # --eval was specified without an argument
            eval_profile = args.profile or os.environ.get("AWS_PROFILE") or "default"
        else:
            # --eval was specified with an explicit profile name
            eval_profile = args.eval

        creds_file = get_aws_credentials_path()
        config = read_aws_credentials(creds_file, auto_decrypt=True)
        if eval_profile not in config:
            print(
                f"Error: Profile '{eval_profile}' not found in credentials file",
                file=sys.stderr,
            )
            if eval_profile == "default":
                print(
                    "\nThe 'default' profile does not exist. You can:",
                    file=sys.stderr,
                )
                print(
                    "  1. Create credentials: iam-sorry --profile iam-sorry <username>",
                    file=sys.stderr,
                )
                print(
                    "  2. Specify a different profile: iam-sorry --eval <profile>",
                    file=sys.stderr,
                )
            sys.exit(1)

        profile = config[eval_profile]

        # Check if credentials need refresh (expired or expiring soon)
        needs_refresh, reason = credentials_need_refresh(profile)
        if needs_refresh:
            print(f"⚠ Credentials expired, refreshing...", file=sys.stderr)

            # Get the IAM username to refresh credentials for
            iam_username = profile.get("credentials_owner")
            if not iam_username:
                print(
                    f"Error: Cannot auto-refresh profile '{eval_profile}' - no credentials_owner field",
                    file=sys.stderr,
                )
                print(
                    "The profile was not created by iam-sorry. Please recreate it.",
                    file=sys.stderr,
                )
                sys.exit(1)

            # Use iam-sorry profile to refresh credentials
            manager_profile = "iam-sorry"
            manager_config = read_aws_credentials(creds_file, auto_decrypt=True)
            if manager_profile not in manager_config:
                print(
                    f"Error: Cannot auto-refresh - '{manager_profile}' profile not found",
                    file=sys.stderr,
                )
                print(
                    f"The '{manager_profile}' profile is required to refresh credentials.",
                    file=sys.stderr,
                )
                sys.exit(1)

            # Validate permission to refresh: check if user is delegated to someone else
            # This prevents the original manager from bypassing delegation via --eval
            try:
                manager_username = get_current_iam_user(manager_profile)
                user_tags = get_user_tags(manager_profile, iam_username)

                if "owner" in user_tags:
                    owner = user_tags["owner"]
                    if owner != manager_username:
                        print(
                            f"Error: Cannot refresh credentials for '{eval_profile}'",
                            file=sys.stderr,
                        )
                        print(
                            f"User '{iam_username}' is delegated to '{owner}' (you are '{manager_username}')",
                            file=sys.stderr,
                        )
                        print(
                            f"Only the owner can refresh delegated user credentials.",
                            file=sys.stderr,
                        )
                        sys.exit(1)
            except Exception as e:
                print(f"Error: Failed to validate refresh permission: {e}", file=sys.stderr)
                sys.exit(1)

            # Generate new temporary credentials (default 36 hours)
            try:
                duration_seconds = 36 * 3600
                new_credentials = get_temp_credentials_for_user(
                    manager_profile, iam_username, duration_seconds
                )
                update_profile_credentials(eval_profile, new_credentials, iam_username)

                # Re-read the updated profile
                config = read_aws_credentials(creds_file, auto_decrypt=True)
                profile = config[eval_profile]

                print(f"✓ Credentials refreshed successfully", file=sys.stderr)
            except Exception as e:
                print(f"Error: Failed to refresh credentials: {e}", file=sys.stderr)
                sys.exit(1)

        access_key = profile.get("aws_access_key_id")
        secret_key = profile.get("aws_secret_access_key")
        session_token = profile.get("aws_session_token")

        if not access_key or not secret_key:
            print(
                f"Error: Profile '{eval_profile}' is missing credentials",
                file=sys.stderr,
            )
            if eval_profile == "default":
                print(
                    "\nThe 'default' profile exists but has no valid credentials.",
                    file=sys.stderr,
                )
                print(
                    "Generate credentials with: iam-sorry --profile iam-sorry <username>",
                    file=sys.stderr,
                )
            sys.exit(1)

        # SECURITY WARNING: If exporting unencrypted iam-sorry profile credentials
        if eval_profile == "iam-sorry":
            # Check if credentials are encrypted by looking at raw data
            raw_config = read_aws_credentials(creds_file, auto_decrypt=False)
            if eval_profile in raw_config:
                raw_access_key = raw_config[eval_profile].get("aws_access_key_id", "")
                raw_secret_key = raw_config[eval_profile].get("aws_secret_access_key", "")

                # If credentials are NOT encrypted, show warning
                if not (raw_access_key.startswith("__encrypted__:") and raw_secret_key.startswith("__encrypted__:")):
                    print(
                        "⚠ WARNING: These are UNENCRYPTED permanent credentials",
                        file=sys.stderr,
                    )
                    print(
                        "For security, these credentials should be encrypted at rest.",
                        file=sys.stderr,
                    )
                    print(
                        "Please encrypt them with: iam-sorry --encrypt",
                        file=sys.stderr,
                    )
                    print(
                        "Then use: eval $(iam-sorry --eval iam-sorry)",
                        file=sys.stderr,
                    )
                    print(file=sys.stderr)

        # Output shell export statements with proper escaping to prevent shell injection
        import shlex

        print(f"export AWS_ACCESS_KEY_ID={shlex.quote(access_key)}")
        print(f"export AWS_SECRET_ACCESS_KEY={shlex.quote(secret_key)}")
        if session_token:
            print(f"export AWS_SESSION_TOKEN={shlex.quote(session_token)}")
        sys.exit(0)

    # Determine which profile to use for managing credentials
    # Default to iam-sorry if not specified
    manager_profile = args.profile or os.environ.get("AWS_PROFILE") or "iam-sorry"

    # Verify the profile exists and decrypt if needed
    creds_file = get_aws_credentials_path()
    temp_config = read_aws_credentials(creds_file, auto_decrypt=True)
    if manager_profile not in temp_config:
        print(
            f"Error: Profile '{manager_profile}' does not exist in credentials file",
            file=sys.stderr,
        )
        if manager_profile == "iam-sorry":
            print(
                f"The default 'iam-sorry' profile is missing. Please specify a different profile with --profile or AWS_PROFILE",
                file=sys.stderr,
            )
        sys.exit(1)

    # Handle --encrypt flag to encrypt the manager profile itself
    if args.encrypt and args.profile_to_manage is None:
        # First, check if credentials are already encrypted (read without auto-decrypt)
        raw_config = read_aws_credentials(creds_file, auto_decrypt=False)

        if manager_profile in raw_config:
            raw_profile = raw_config[manager_profile]
            raw_access_key = raw_profile.get("aws_access_key_id", "")
            raw_secret_key = raw_profile.get("aws_secret_access_key", "")

            # Check if already encrypted
            if raw_access_key.startswith("__encrypted__:") and raw_secret_key.startswith("__encrypted__:"):
                print(
                    f"Error: Manager profile '{manager_profile}' is already encrypted",
                    file=sys.stderr,
                )
                print(
                    "No need to encrypt again.",
                    file=sys.stderr,
                )
                sys.exit(1)

        # Now read with auto-decrypt for the encryption process
        config = read_aws_credentials(creds_file, auto_decrypt=True)

        print(f"Encrypting manager profile '{manager_profile}'...")

        # Get current credentials and encrypt them
        profile_creds = config[manager_profile]
        access_key = profile_creds.get("aws_access_key_id")
        secret_key = profile_creds.get("aws_secret_access_key")
        session_token = profile_creds.get("aws_session_token")
        owner = profile_creds.get("credentials_owner")

        if not access_key or not secret_key:
            print(
                f"Error: Manager profile '{manager_profile}' missing access key or secret key",
                file=sys.stderr,
            )
            sys.exit(1)

        # Encrypt the credentials
        ssh_key_path = get_ssh_key_path()
        encrypted_access_key = encrypt_credential(access_key, ssh_key_path)
        encrypted_secret_key = encrypt_credential(secret_key, ssh_key_path)

        # Update the profile with encrypted credentials
        config[manager_profile]["aws_access_key_id"] = encrypted_access_key
        config[manager_profile]["aws_secret_access_key"] = encrypted_secret_key

        write_aws_credentials(creds_file, config)

        print(f"✓ Manager profile '{manager_profile}' encrypted with SSH key")
        sys.exit(0)

    # If no profile_to_manage is specified, default to the management profile
    if args.profile_to_manage is None:
        args.profile_to_manage = manager_profile

    # CRITICAL: Prevent refreshing the management profile (permanent credentials should never be replaced)
    if args.profile_to_manage == manager_profile or args.profile_to_manage == "iam-sorry":
        print(
            f"Error: The '{args.profile_to_manage}' profile contains permanent manager credentials",
            file=sys.stderr,
        )
        print(
            "This profile should NEVER be refreshed with temporary credentials.",
            file=sys.stderr,
        )
        print(
            "The iam-sorry profile is for credential management only, not for direct AWS operations.",
            file=sys.stderr,
        )
        print(
            "\nIf you need to use AWS, generate credentials for a different profile:",
            file=sys.stderr,
        )
        print(
            f"  ./iam-sorry iam-bedrock    # Create and use a temporary profile instead",
            file=sys.stderr,
        )
        sys.exit(1)

    # CRITICAL: Enforce encryption for iam-sorry profile (when actually using it)
    # The iam-sorry profile contains permanent manager credentials and MUST be encrypted
    if manager_profile == "iam-sorry":
        # Read WITHOUT auto-decrypt to check if credentials are encrypted
        raw_config = read_aws_credentials(creds_file, auto_decrypt=False)
        if manager_profile in raw_config:
            access_key = raw_config[manager_profile].get("aws_access_key_id", "")
            secret_key = raw_config[manager_profile].get("aws_secret_access_key", "")

            # Check if credentials are encrypted
            if not (access_key.startswith("__encrypted__:") and secret_key.startswith("__encrypted__:")):
                print(
                    "⚠ ERROR: The 'iam-sorry' profile contains UNENCRYPTED permanent credentials",
                    file=sys.stderr,
                )
                print(
                    "For security, manager credentials must be encrypted at rest.",
                    file=sys.stderr,
                )
                print(
                    "\nTo encrypt the credentials, run:",
                    file=sys.stderr,
                )
                print(
                    "  iam-sorry --encrypt",
                    file=sys.stderr,
                )
                print(
                    "\nThis will encrypt your credentials using your ED25519 SSH key.",
                    file=sys.stderr,
                )
                sys.exit(1)

    # Validate duration (convert hours to seconds)
    if args.duration < 1:  # Minimum 1 hour
        print("Error: Duration must be at least 1 hour", file=sys.stderr)
        sys.exit(1)

    if args.duration > 36:  # 36 hours maximum for GetSessionToken
        print("Error: Duration cannot exceed 36 hours", file=sys.stderr)
        sys.exit(1)

    # Convert hours to seconds for the API call
    duration_seconds = args.duration * 3600

    print(f"Target profile: '{args.profile_to_manage}'")

    # Determine the IAM username
    creds_file = get_aws_credentials_path()
    # Auto-decrypt encrypted credentials when needed
    creds_config = read_aws_credentials(creds_file, auto_decrypt=True)

    if args.profile_to_manage in creds_config:
        # Profile exists - check if we have a stored IAM username first
        print(f"Profile '{args.profile_to_manage}' exists, looking up IAM user...")

        # Try to get the stored IAM username (for profiles with temporary credentials)
        iam_username = creds_config[args.profile_to_manage].get("credentials_owner")

        if not iam_username:
            # Fall back to looking up by access key (for profiles with permanent credentials)
            access_key = creds_config[args.profile_to_manage].get("aws_access_key_id")

            if not access_key:
                print(
                    f"Error: Profile '{args.profile_to_manage}' has no aws_access_key_id",
                    file=sys.stderr,
                )
                sys.exit(1)

            iam_username = get_iam_user_for_access_key(manager_profile, access_key)

        if not iam_username:
            print(
                f"Error: Could not determine IAM user for profile '{args.profile_to_manage}'",
                file=sys.stderr,
            )
            sys.exit(1)

        print(f"IAM user: {iam_username}")
    else:
        # Profile doesn't exist - treat as IAM username
        iam_username = args.profile_to_manage
        print(f"Profile doesn't exist, treating '{iam_username}' as IAM username...")

        # Get the manager's username for validation
        manager_username = get_current_iam_user(manager_profile)

        # Validate prefix FIRST (before any AWS API calls to user/tags)
        # If --chown is specified, validate against the owner's prefix
        # Otherwise, validate against the manager's prefix
        if args.chown:
            owner_username = args.chown
            is_valid, reason = validate_username_prefix(owner_username, iam_username)
            if not is_valid:
                print(
                    f"Error: When delegating to '{owner_username}', the user must match their prefix",
                    file=sys.stderr,
                )
                print(f"Details: {reason}", file=sys.stderr)
                sys.exit(1)
        else:
            # Normal case: validate prefix matching for manager
            is_valid, reason = validate_username_prefix(manager_username, iam_username)
            if not is_valid:
                print(f"Error: {reason}", file=sys.stderr)
                sys.exit(1)

        # After prefix validation passes, check if user exists
        user_exists = verify_iam_user_exists(manager_profile, iam_username)

        # If --chown and user EXISTS, check tags to prevent re-chown
        if args.chown and user_exists:
            existing_tags = get_user_tags(manager_profile, iam_username)
            if "owner" in existing_tags:
                print(
                    f"Error: User '{iam_username}' is already delegated to '{existing_tags['owner']}'",
                    file=sys.stderr,
                )
                print(
                    f"Cannot re-delegate an already delegated user (one-time operation only)",
                    file=sys.stderr,
                )
                sys.exit(1)

        # Now create user if needed (prefix validation already passed)
        if not user_exists:
            print(f"Creating IAM user '{iam_username}'...")
            try:
                create_iam_user(manager_profile, iam_username)
                print(f"✓ IAM user '{iam_username}' created")
            except Exception as e:
                print(f"Error: Failed to create IAM user '{iam_username}': {e}", file=sys.stderr)
                sys.exit(1)
        else:
            print(f"IAM user verified: {iam_username}")

    # For profiles that already exist, we need to validate and check delegation
    # (The new user path already did this validation above)
    if args.profile_to_manage in creds_config:
        # Get manager username if we don't have it yet
        if 'manager_username' not in locals():
            manager_username = get_current_iam_user(manager_profile)

        if args.chown:
            # With --chown, validate against owner's prefix
            owner_username = args.chown
            is_valid, reason = validate_username_prefix(owner_username, iam_username)
            if not is_valid:
                print(
                    f"Error: When delegating to '{owner_username}', the user must match their prefix",
                    file=sys.stderr,
                )
                print(f"Details: {reason}", file=sys.stderr)
                sys.exit(1)

            print(f"⚠ Delegating user '{iam_username}' to '{owner_username}' (one-time operation)")
        else:
            # Normal case: validate prefix matching
            is_valid, reason = validate_username_prefix(manager_username, iam_username)
            if not is_valid:
                print(f"Error: {reason}", file=sys.stderr)
                sys.exit(1)

            # Check if user is delegated to someone else (read-only access for manager)
            user_tags = get_user_tags(manager_profile, iam_username)
            if "owner" in user_tags:
                owner = user_tags["owner"]
                if owner != manager_username:
                    print(
                        f"⚠ User '{iam_username}' is delegated to '{owner}'",
                        file=sys.stderr,
                    )
                    print(
                        f"You can view this user but cannot manage credentials (read-only access)",
                        file=sys.stderr,
                    )
                    sys.exit(0)
    elif args.chown:
        # For new users with --chown, print delegation message
        owner_username = args.chown
        print(f"⚠ Delegating user '{iam_username}' to '{owner_username}' (one-time operation)")

    print(f"Requesting temporary credentials (valid for {args.duration} hours)...")

    # Get temporary credentials
    credentials = get_temp_credentials_for_user(manager_profile, iam_username, duration_seconds)

    # Determine if we should encrypt: only if target profile is the manager profile
    # (i.e., we're storing the powerful permanent credentials, not temp credentials)
    should_encrypt = args.encrypt and (args.profile_to_manage == manager_profile)

    # Update the profile (with optional encryption only for manager profile)
    update_profile_credentials(
        args.profile_to_manage, credentials, iam_username, encrypt=should_encrypt
    )

    # Apply delegation tags if --chown is specified
    if args.chown:
        import time

        max_retries = 3
        retry_delay = 0.5  # seconds

        for attempt in range(max_retries):
            try:
                # Re-check tags immediately before applying to prevent race condition
                # Between initial check and now, another process could have added tags
                current_tags = get_user_tags(manager_profile, iam_username)
                if "owner" in current_tags:
                    print(
                        f"Error: Race condition detected - user '{iam_username}' was delegated to '{current_tags['owner']}' by another process",
                        file=sys.stderr,
                    )
                    print(
                        f"This user is already delegated and cannot be re-delegated.",
                        file=sys.stderr,
                    )
                    sys.exit(1)

                # Apply tags
                tags_to_apply = {
                    "owner": owner_username,
                    "delegated-by": manager_username,
                }
                tag_user(manager_profile, iam_username, tags_to_apply)
                print(f"✓ Applied delegation tags:")
                print(f"  - owner: {owner_username}")
                print(f"  - delegated-by: {manager_username}")
                break  # Success, exit retry loop

            except Exception as e:
                if attempt < max_retries - 1:
                    # Retry after delay (might be transient AWS API issue)
                    print(
                        f"⚠ Tag application attempt {attempt + 1} failed, retrying...",
                        file=sys.stderr,
                    )
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    # Final attempt failed
                    print(f"Error: Failed to apply delegation tags after {max_retries} attempts: {e}", file=sys.stderr)
                    sys.exit(1)

    expiration = credentials["Expiration"]
    print(f"✓ Successfully updated profile '{args.profile_to_manage}'")
    print(f"✓ IAM user: {iam_username}")
    print(f"✓ Credentials expire at: {expiration}")
    if should_encrypt:
        print(f"✓ Credentials encrypted with SSH key")
    elif args.encrypt:
        print(
            f"ℹ Encryption only applies to manager profile (--profile), not generated temporary credentials"
        )
    if args.chown:
        print(f"ℹ User delegated to '{owner_username}' - they can now manage their own credentials")

    return 0


if __name__ == "__main__":
    sys.exit(main())
