"""
Command-line interface for iam-sorry.
"""

import argparse
import json
import os
import sys

from .core import (
    encrypt_credential,
    generate_usermanager_policy,
    get_aws_account_id,
    get_aws_credentials_path,
    get_current_iam_user,
    get_iam_user_for_access_key,
    get_ssh_key_path,
    get_temp_credentials_for_user,
    read_aws_credentials,
    update_profile_credentials,
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
        "--show-encrypted",
        metavar="PROFILE",
        help="Show encrypted credentials for a profile (for debugging)",
    )
    parser.add_argument(
        "--show-decrypted",
        metavar="PROFILE",
        help="Show decrypted credentials for a profile",
    )
    parser.add_argument(
        "--eval",
        metavar="PROFILE",
        nargs="?",
        const=None,
        help="Output shell export statements for a profile's credentials (for eval in shell scripts). If no profile specified, uses --profile value.",
    )
    parser.add_argument(
        "--print-policy",
        action="store_true",
        help="Print the recommended IAM policy for the current user (personalized with account ID and username)",
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
            policy = generate_usermanager_policy(manager_profile)

            # Print with nice formatting
            print(f"# IAM Policy for usermanager: {current_user}")
            print(f"# Account: {policy['Statement'][0]['Resource'].split(':')[4]}")
            print(f"# Generated for: {current_user}")
            print()
            print(json.dumps(policy, indent=2))
            sys.exit(0)
        except Exception as e:
            print(f"Error: Failed to generate policy: {e}", file=sys.stderr)
            sys.exit(1)

    # Handle --show-encrypted flag for debugging
    if args.show_encrypted:
        creds_file = get_aws_credentials_path()
        config = read_aws_credentials(creds_file, auto_decrypt=False)
        if args.show_encrypted not in config:
            print(f"Error: Profile '{args.show_encrypted}' not found", file=sys.stderr)
            sys.exit(1)

        profile = config[args.show_encrypted]
        print(f"Profile: {args.show_encrypted}")
        print(f"Access Key ID: {profile.get('aws_access_key_id', 'N/A')}")
        print(f"Secret Access Key: {profile.get('aws_secret_access_key', 'N/A')}")
        print(f"Session Token: {profile.get('aws_session_token', 'N/A')}")
        sys.exit(0)

    # Handle --show-decrypted flag
    if args.show_decrypted:
        creds_file = get_aws_credentials_path()
        config = read_aws_credentials(creds_file, auto_decrypt=True)
        if args.show_decrypted not in config:
            print(f"Error: Profile '{args.show_decrypted}' not found", file=sys.stderr)
            sys.exit(1)

        profile = config[args.show_decrypted]
        print(f"Profile: {args.show_decrypted}")
        print(f"Access Key ID: {profile.get('aws_access_key_id', 'N/A')}")
        print(f"Secret Access Key: {profile.get('aws_secret_access_key', 'N/A')}")
        print(f"Session Token: {profile.get('aws_session_token', 'N/A')}")
        if "credentials_owner" in profile:
            print(f"Credentials Owner: {profile.get('credentials_owner')}")
        sys.exit(0)

    # Handle --eval flag to output shell export statements
    if args.eval is not None:
        # If --eval has no argument, use the --profile value, default to iam-sorry
        eval_profile = (
            args.eval if args.eval else args.profile or os.environ.get("AWS_PROFILE") or "iam-sorry"
        )

        creds_file = get_aws_credentials_path()
        config = read_aws_credentials(creds_file, auto_decrypt=True)
        if eval_profile not in config:
            print(f"Error: Profile '{eval_profile}' not found", file=sys.stderr)
            sys.exit(1)

        profile = config[eval_profile]
        access_key = profile.get("aws_access_key_id")
        secret_key = profile.get("aws_secret_access_key")
        session_token = profile.get("aws_session_token")

        if not access_key or not secret_key:
            print(f"Error: Profile '{eval_profile}' missing credentials", file=sys.stderr)
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

    # Verify the profile exists
    creds_file = get_aws_credentials_path()
    temp_config = read_aws_credentials(creds_file, auto_decrypt=False)
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

    # If no profile_to_manage is specified, ask about iam-sorry profile
    if args.profile_to_manage is None:
        creds_file = get_aws_credentials_path()
        # Auto-decrypt encrypted credentials when needed
        creds_config = read_aws_credentials(creds_file, auto_decrypt=True)

        if "iam-sorry" not in creds_config:
            print(
                "Error: 'iam-sorry' profile does not exist in credentials file",
                file=sys.stderr,
            )
            sys.exit(1)

        # Verify the iam-sorry profile has credentials and can determine user
        access_key = creds_config["iam-sorry"].get("aws_access_key_id")
        if not access_key:
            print(
                "Error: 'iam-sorry' profile has no aws_access_key_id",
                file=sys.stderr,
            )
            sys.exit(1)

        # Verify we can determine the IAM user for the iam-sorry profile
        iam_username = get_iam_user_for_access_key(manager_profile, access_key)
        if not iam_username:
            print(
                "Error: Could not determine IAM user for 'iam-sorry' profile",
                file=sys.stderr,
            )
            sys.exit(1)

        # Ask user for confirmation
        print(f"No profile specified. Found 'iam-sorry' profile with user: {iam_username}")
        response = (
            input("Do you want to refresh credentials for the 'iam-sorry' profile? (y/n): ")
            .strip()
            .lower()
        )

        if response != "y":
            print("Aborted.")
            sys.exit(0)

        args.profile_to_manage = "iam-sorry"

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

    return 0


if __name__ == "__main__":
    sys.exit(main())
