"""
Command-line interface for iam-sorry.
"""

import argparse
import json
import os
import sys

from .core import (
    credentials_need_refresh,
    encrypt_credential,
    generate_usermanager_policy,
    get_aws_account_id,
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
        help="AWS profile to use for credential management (defaults to AWS_PROFILE env var)",
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
        help="Encrypt the manager profile permanent credentials (only for --profile argument, not generated temp credentials)",
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
        action="store_true",
        help="Print the recommended IAM policy for the current user (personalized with account ID and username)",
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
        "If not, treats it as an IAM username. If omitted, will prompt to use 'iam-sorry' profile.",
    )

    args = parser.parse_args()

    # Handle --print-policy flag
    if args.print_policy:
        # Determine which profile to use for getting user/account info
        # Default to iam-sorry if not specified
        manager_profile = args.profile or os.environ.get("AWS_PROFILE") or "iam-sorry"

        try:
            current_user = get_current_iam_user(manager_profile)
            account_id = get_aws_account_id(manager_profile)
            policy = generate_usermanager_policy(manager_profile)

            # Print with nice formatting
            print(f"# IAM Policy for usermanager: {current_user}")
            print(f"# Account: {account_id}")
            print(f"# Generated for: {current_user}")
            print()
            print(json.dumps(policy, indent=2))
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

        # Output shell export statements
        print(f"export AWS_ACCESS_KEY_ID='{access_key}'")
        print(f"export AWS_SECRET_ACCESS_KEY='{secret_key}'")
        if session_token:
            print(f"export AWS_SESSION_TOKEN='{session_token}'")
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

    # If no profile_to_manage is specified, show usage error
    if args.profile_to_manage is None:
        print(
            "Error: No profile or IAM username specified",
            file=sys.stderr,
        )
        print(
            "\nUsage examples:",
            file=sys.stderr,
        )
        print(
            "  iam-sorry --profile iam-sorry admin    # Generate temp credentials for 'admin' user",
            file=sys.stderr,
        )
        print(
            "  iam-sorry --profile iam-sorry newuser  # Generate credentials for new IAM user",
            file=sys.stderr,
        )
        print(
            "  iam-sorry --eval default               # Export credentials from 'default' profile",
            file=sys.stderr,
        )
        print(
            "\nNote: The 'iam-sorry' profile contains permanent manager credentials and should not be refreshed.",
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

        # Verify the user exists
        if not verify_iam_user_exists(manager_profile, iam_username):
            print(
                f"Error: IAM user '{iam_username}' does not exist",
                file=sys.stderr,
            )
            sys.exit(1)

        print(f"IAM user verified: {iam_username}")

    # Validate username prefix (manager can only manage users with matching prefix)
    # UNLESS --chown is specified (one-time delegation)
    # Get the manager's username first
    manager_username = get_current_iam_user(manager_profile)

    if args.chown:
        # With --chown, we bypass prefix validation (one-time delegation to another user)
        owner_username = args.chown
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

    print(f"Requesting temporary credentials (valid for {args.duration} hours)...")

    # Get temporary credentials
    credentials = get_temp_credentials_for_user(manager_profile, iam_username, duration_seconds)

    # Determine if we should encrypt: only if target profile is the manager profile
    # (i.e., we're storing the powerful permanent credentials, not temp credentials)
    should_encrypt = args.encrypt and (args.profile_to_manage == manager_profile)

    # Check if user already has owner tag (prevent re-chown)
    if args.chown:
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

    # Update the profile (with optional encryption only for manager profile)
    update_profile_credentials(
        args.profile_to_manage, credentials, iam_username, encrypt=should_encrypt
    )

    # Apply delegation tags if --chown is specified
    if args.chown:
        try:
            tags_to_apply = {
                "owner": owner_username,
                "delegated-by": manager_username,
            }
            tag_user(manager_profile, iam_username, tags_to_apply)
            print(f"✓ Applied delegation tags:")
            print(f"  - owner: {owner_username}")
            print(f"  - delegated-by: {manager_username}")
        except Exception as e:
            print(f"Error: Failed to apply delegation tags: {e}", file=sys.stderr)
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
