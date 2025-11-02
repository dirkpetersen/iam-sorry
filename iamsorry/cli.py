"""
Command-line interface for iam-sorry.
"""

import argparse
import configparser
import json
import os
import sys
from pathlib import Path

from botocore.exceptions import ClientError

from .core import (
    create_access_key_for_user,
    create_iam_role,
    create_iam_user,
    create_session_with_profile,
    credentials_need_refresh,
    encrypt_credential,
    extract_username_prefix,
    fix_aws_profiles,
    generate_refresh_only_policy,
    generate_usermanager_policy,
    get_aws_account_id,
    get_aws_config_path,
    get_aws_credentials_path,
    get_current_iam_user,
    get_iam_user_for_access_key,
    get_profile_source_profile,
    get_ssh_key_path,
    get_temp_credentials_for_user,
    get_user_tags,
    is_ssh_key_password_protected,
    put_user_policy,
    read_aws_credentials,
    reset_iam_sorry_profile,
    tag_user,
    update_profile_credentials,
    validate_username_prefix,
    verify_iam_role_exists,
    verify_iam_user_exists,
    write_aws_credentials,
    write_role_profile_config,
)


def try_auto_bootstrap_iam_sorry():
    """
    Attempt to auto-bootstrap iam-sorry profile from environment variables.

    Returns: True if successfully bootstrapped, False otherwise.

    Trigger conditions (ALL must be true):
    - iam-sorry profile does NOT exist yet
    - AWS credentials are in environment variables
    - Either permanent (AKIA*) or temporary (ASIA*) credentials

    Flow:
    - If temporary (ASIA*): Create permanent access key using iam:CreateAccessKey
    - Encrypt permanent credentials with SSH key
    - Store in [iam-sorry] profile
    """
    import boto3

    # Check if iam-sorry profile already exists
    creds_file = get_aws_credentials_path()
    config = read_aws_credentials(creds_file, auto_decrypt=False)

    if "iam-sorry" in config:
        return None  # Profile already exists, don't auto-bootstrap

    # Check if AWS credentials are in environment
    env_access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    env_secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    env_session_token = os.environ.get("AWS_SESSION_TOKEN")

    if not env_access_key or not env_secret_key:
        return False  # No credentials in environment

    # Determine if credentials are temporary
    is_temporary = bool(env_session_token) or env_access_key.startswith("ASIA")

    print()
    print("=" * 70)
    print("Auto-Bootstrapping iam-sorry Profile")
    print("=" * 70)
    print()
    print(f"Using AWS_ACCESS_KEY_ID: {env_access_key}")
    print()

    final_access_key = env_access_key
    final_secret_key = env_secret_key

    if is_temporary:
        # Use temporary credentials to create a permanent key
        print("Environment credentials: TEMPORARY (will create permanent key)")
        print()

        try:
            session = boto3.Session(
                aws_access_key_id=env_access_key,
                aws_secret_access_key=env_secret_key,
                aws_session_token=env_session_token,
            )

            # First, verify credentials are valid with GetCallerIdentity
            print("Verifying temporary credentials...")
            sts_client = session.client("sts")
            try:
                identity = sts_client.get_caller_identity()
                arn = identity["Arn"]
                print(f"✓ Credentials are valid")
            except ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "InvalidClientTokenId":
                    print(f"Error: Temporary credentials are invalid or expired", file=sys.stderr)
                    print(
                        "The session token in your environment variables is no longer valid.",
                        file=sys.stderr,
                    )
                    print()
                    print("This can happen if:", file=sys.stderr)
                    print("  • The temporary credentials have expired (36+ hours old)", file=sys.stderr)
                    print("  • The session was revoked or invalidated", file=sys.stderr)
                    print("  • The credentials were created in a different AWS account", file=sys.stderr)
                    print()
                    print("Solution:", file=sys.stderr)
                    print("  Contact your administrator for fresh temporary credentials.", file=sys.stderr)
                    print("  Then re-export them and run: iam-sorry", file=sys.stderr)
                else:
                    print(f"Error: Failed to verify credentials ({error_code})", file=sys.stderr)
                    print(f"Details: {e}", file=sys.stderr)
                return False

            # Validate it's a user ARN
            if ":user/" not in arn:
                print(f"Error: Cannot auto-bootstrap with non-user credentials", file=sys.stderr)
                print(f"Current identity: {arn}", file=sys.stderr)
                print(
                    "The iam-sorry profile requires IAM user credentials, not role/federated credentials.",
                    file=sys.stderr,
                )
                return False

            current_username = arn.split(":user/")[1]
            print(f"Current IAM user: {current_username}")
            print()

            # Create access key with retry logic for eventual consistency
            print("Creating new permanent access key...")
            import time
            iam_client = session.client("iam")

            max_retries = 5
            retry_delay = 3  # Start with 3 seconds
            new_access_key = None

            for attempt in range(max_retries):
                try:
                    response = iam_client.create_access_key(UserName=current_username)
                    new_access_key = response["AccessKey"]
                    break  # Success!
                except ClientError as retry_error:
                    retry_code = retry_error.response["Error"]["Code"]
                    if retry_code == "InvalidClientTokenId" and attempt < max_retries - 1:
                        # Temporary credentials not yet propagated in IAM
                        print(f"⏳ Waiting {retry_delay}s for credential propagation (attempt {attempt + 1}/{max_retries})...")
                        time.sleep(retry_delay)
                        retry_delay *= 1.5  # Exponential backoff
                    else:
                        # Different error or final attempt - let outer handler catch it
                        raise

            if new_access_key is None:
                raise Exception("Failed to create access key after multiple retry attempts")

            final_access_key = new_access_key["AccessKeyId"]
            final_secret_key = new_access_key["SecretAccessKey"]

            print(f"✓ New permanent access key created: {final_access_key[:10]}***")

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "InvalidClientTokenId":
                print(f"Error: Temporary credentials are expired or invalid", file=sys.stderr)
                print(
                    "The session token in your environment variables is no longer valid.",
                    file=sys.stderr,
                )
                print()
                print("This can happen if:", file=sys.stderr)
                print("  • The temporary credentials have expired (36+ hours old)", file=sys.stderr)
                print("  • The session was revoked or invalidated", file=sys.stderr)
                print("  • The credentials were created in a different AWS account", file=sys.stderr)
                print()
                print("Solution:", file=sys.stderr)
                print("  Contact your administrator for fresh temporary credentials.", file=sys.stderr)
                print("  Then re-export them and run: iam-sorry", file=sys.stderr)
                print()
                print("  Alternatively, if you have permanent credentials (AKIA*), use those instead.", file=sys.stderr)
            elif error_code == "AccessDenied":
                print(f"Error: Cannot create access key - permission denied", file=sys.stderr)
                print(
                    "Your temporary credentials do not have iam:CreateAccessKey permission.",
                    file=sys.stderr,
                )
                print()
                print("This can happen if:", file=sys.stderr)
                print(f"  • The user '{current_username}' doesn't have iam:CreateAccessKey for itself", file=sys.stderr)
                print("  • The temporary credentials were created without sufficient permissions", file=sys.stderr)
                print()
                print("Solution:", file=sys.stderr)
                print("  Contact your administrator to:", file=sys.stderr)
                print("  1. Ensure the user has iam:CreateAccessKey permission", file=sys.stderr)
                print("  2. Generate fresh temporary credentials with this permission", file=sys.stderr)
                print("  3. Or provide permanent credentials (AKIA) instead", file=sys.stderr)
            else:
                print(f"Error: Failed to create access key ({error_code})", file=sys.stderr)
                print(f"Details: {e}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"Error: Failed to create access key", file=sys.stderr)
            print(f"Details: {e}", file=sys.stderr)
            return False
    else:
        print(f"Environment credentials: PERMANENT (will rotate after bootstrap)")
        print()
        print("For security, will attempt to create new permanent credentials and disable admin-provided ones...")
        print("(Note: If rotation fails, the admin-provided credentials will be used directly.)")

        # Try to create new permanent credentials to replace the admin-provided ones
        try:
            import boto3
            session = boto3.Session(
                aws_access_key_id=env_access_key,
                aws_secret_access_key=env_secret_key
            )

            # Get current user
            sts_client = session.client("sts")
            identity = sts_client.get_caller_identity()
            arn = identity["Arn"]

            if ":user/" not in arn:
                print(f"Warning: Cannot rotate credentials for non-user identity: {arn}", file=sys.stderr)
                print("Will use admin-provided credentials directly.", file=sys.stderr)
                final_access_key = env_access_key
                final_secret_key = env_secret_key
            else:
                current_username = arn.split(":user/")[1]
                print(f"Current IAM user: {current_username}")

                # Create new access key
                print("Creating new permanent access key...")
                iam_client = session.client("iam")
                response = iam_client.create_access_key(UserName=current_username)
                new_access_key = response["AccessKey"]

                new_access_key_id = new_access_key["AccessKeyId"]
                new_secret_key = new_access_key["SecretAccessKey"]

                print(f"✓ New access key created: {new_access_key_id[:10]}***")

                # Test the new key works before deleting the old one
                print("Testing new access key...")
                import time
                test_passed = False
                max_retries = 5
                retry_delay = 2

                for attempt in range(max_retries):
                    try:
                        test_session = boto3.Session(
                            aws_access_key_id=new_access_key_id,
                            aws_secret_access_key=new_secret_key
                        )
                        test_sts = test_session.client("sts")
                        test_identity = test_sts.get_caller_identity()
                        print(f"✓ New access key verified: {test_identity['Arn']}")
                        test_passed = True
                        break
                    except Exception as test_error:
                        if attempt < max_retries - 1:
                            print(f"  ⏳ Waiting {retry_delay}s for key propagation (attempt {attempt + 1}/{max_retries})...")
                            time.sleep(retry_delay)
                            retry_delay *= 1.5
                        else:
                            print(f"Error: New access key failed verification: {test_error}", file=sys.stderr)

                if not test_passed:
                    # New key doesn't work, delete it and keep using the old one
                    print("Cleaning up failed new access key...")
                    try:
                        iam_client.delete_access_key(
                            UserName=current_username,
                            AccessKeyId=new_access_key_id
                        )
                        print("✓ Failed access key cleaned up")
                    except:
                        pass
                    print("Will continue using admin-provided credentials.", file=sys.stderr)
                    final_access_key = env_access_key
                    final_secret_key = env_secret_key
                else:
                    # New key works, now safe to disable/delete the old one
                    try:
                        # First try to disable the old key (safer - can be re-enabled if needed)
                        print(f"Disabling admin-provided access key: {env_access_key[:10]}***")
                        iam_client.update_access_key(
                            UserName=current_username,
                            AccessKeyId=env_access_key,
                            Status='Inactive'
                        )
                        print(f"✓ Admin-provided access key disabled (status: Inactive)")
                        print(f"  Note: The old key still exists but is disabled. Delete it manually if not needed.")
                        print(f"  AWS Console: IAM → Users → {current_username} → Security credentials")
                    except Exception as disable_error:
                        # If we can't disable, try to delete
                        try:
                            print(f"Could not disable, attempting to delete old access key: {env_access_key[:10]}***")
                            iam_client.delete_access_key(
                                UserName=current_username,
                                AccessKeyId=env_access_key
                            )
                            print(f"✓ Admin-provided access key deleted")
                        except Exception as delete_error:
                            print(f"Warning: Could not disable or delete old access key: {delete_error}", file=sys.stderr)
                            print("You should manually disable/delete it for security.", file=sys.stderr)
                            print(f"AWS Console: IAM → Users → {current_username} → Security credentials", file=sys.stderr)

                    final_access_key = new_access_key_id
                    final_secret_key = new_secret_key

        except Exception as e:
            print(f"Warning: Could not rotate credentials: {e}", file=sys.stderr)
            print()
            print("This typically means:", file=sys.stderr)
            print("  • The admin-provided credentials are no longer valid", file=sys.stderr)
            print("  • The IAM user has been deleted or disabled", file=sys.stderr)
            print("  • Access keys were revoked or removed", file=sys.stderr)
            print()
            print("SOLUTION: Contact your system administrator to provide fresh credentials.", file=sys.stderr)
            print("The bootstrap cannot proceed without valid credentials.", file=sys.stderr)
            print()
            return False

    print()
    print("Validating SSH key...")

    # Validate SSH key is password protected
    ssh_key_path = get_ssh_key_path()
    is_protected = is_ssh_key_password_protected(ssh_key_path)

    if is_protected is False:
        print(f"Error: SSH key '{ssh_key_path}' is not password protected.", file=sys.stderr)
        print(
            "For security, only password-protected SSH keys can be used for encryption.",
            file=sys.stderr,
        )
        print(f"Add a passphrase: ssh-keygen -p -f {ssh_key_path}", file=sys.stderr)
        return False
    elif is_protected is None:
        print(
            f"Error: Could not verify if SSH key '{ssh_key_path}' is password protected.",
            file=sys.stderr,
        )
        print("Please ensure it's a valid OPENSSH format key.", file=sys.stderr)
        return False

    print("✓ SSH key is password-protected")
    print()
    print("Encrypting credentials...")

    # Encrypt credentials
    try:
        encrypted_access_key = encrypt_credential(final_access_key, ssh_key_path)
        encrypted_secret_key = encrypt_credential(final_secret_key, ssh_key_path)
    except Exception as e:
        print(f"Error: Failed to encrypt credentials", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        return False

    # Write to profile
    try:
        creds_config = read_aws_credentials(creds_file, auto_decrypt=False)
        creds_config["iam-sorry"] = {
            "aws_access_key_id": encrypted_access_key,
            "aws_secret_access_key": encrypted_secret_key,
        }
        write_aws_credentials(creds_file, creds_config)
    except Exception as e:
        print(f"Error: Failed to write credentials", file=sys.stderr)
        print(f"Details: {e}", file=sys.stderr)
        return False

    print("✓ Credentials encrypted and stored")
    print()

    # Determine region for config file
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")

    if not region:
        # Try to read from existing config
        try:
            config_file = get_aws_config_path()
            config_parser = configparser.ConfigParser()
            config_parser.optionxform = str
            if os.path.exists(config_file):
                config_parser.read(config_file)
                # Try to get region from existing profile sections
                if "profile iam-sorry" in config_parser:
                    region = config_parser["profile iam-sorry"].get("region")
                elif "default" in config_parser:
                    region = config_parser["default"].get("region")
        except (OSError, configparser.Error):
            pass

    # Default to us-west-2 if no region found
    if not region:
        region = "us-west-2"

    print(f"Configuring region: {region}")

    # Write config file with region
    try:
        config_file = get_aws_config_path()
        config_parser = configparser.ConfigParser()
        config_parser.optionxform = str

        if os.path.exists(config_file):
            config_parser.read(config_file)

        # Set iam-sorry profile in config
        config_parser["profile iam-sorry"] = {"region": region}

        Path(config_file).parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, "w") as f:
            config_parser.write(f)
        os.chmod(config_file, 0o644)

        print(f"✓ Config file updated: ~/.aws/config")
    except Exception as e:
        print(f"⚠ Warning: Could not update config file: {e}", file=sys.stderr)

    # After successful bootstrap, create the base user if it doesn't exist
    # This ensures the base user is available for role creation
    print()
    print("Checking if base user needs to be created...")

    try:
        import boto3
        # Create a temporary session with the newly bootstrapped credentials
        bootstrap_session = create_session_with_profile("iam-sorry")
        sts_client = bootstrap_session.client("sts")

        # Get the current user to determine the prefix
        identity = sts_client.get_caller_identity()
        arn = identity["Arn"]

        if ":user/" in arn:
            username = arn.split(":user/")[1]
            prefix = extract_username_prefix(username)
            base_username = prefix

            # Check if base user exists
            if not verify_iam_user_exists("iam-sorry", base_username):
                print(f"Creating base user '{base_username}' for role assumption...")
                create_iam_user("iam-sorry", base_username)
                print(f"✓ Base user '{base_username}' created")

                # Generate credentials for the base user
                # IMPORTANT: GetSessionToken returns creds for CALLING user, not specified user
                # So we must: 1) create access key for base user, 2) use it to call GetSessionToken, 3) delete it
                print(f"Generating credentials for '{base_username}'...")

                try:
                    # Step 1: Create temporary access key for base user
                    print(f"  Creating temporary access key for '{base_username}'...")
                    base_access_key = create_access_key_for_user("iam-sorry", base_username)
                    print(f"  ✓ Temporary access key created: {base_access_key['AccessKeyId'][:10]}***")

                    # Step 2: Use base user credentials to call GetSessionToken AS the base user
                    base_user_session = boto3.Session(
                        aws_access_key_id=base_access_key['AccessKeyId'],
                        aws_secret_access_key=base_access_key['SecretAccessKey']
                    )

                    # Retry with exponential backoff for propagation delays
                    import time
                    max_retries = 5
                    retry_delay = 2
                    temp_creds = None

                    for attempt in range(max_retries):
                        try:
                            base_sts = base_user_session.client('sts')
                            response = base_sts.get_session_token(DurationSeconds=36 * 3600)
                            temp_creds = response['Credentials']
                            print(f"  ✓ Session token generated for '{base_username}'")
                            break
                        except ClientError as e:
                            error_code = e.response['Error']['Code']
                            if error_code == 'InvalidClientTokenId' and attempt < max_retries - 1:
                                print(f"  ⏳ Waiting {retry_delay}s for access key propagation (attempt {attempt + 1}/{max_retries})...")
                                time.sleep(retry_delay)
                                retry_delay *= 1.5
                            else:
                                raise

                    if temp_creds is None:
                        raise Exception("Failed to generate session token after multiple retries")

                    # Step 3: Delete the temporary access key
                    print(f"  Deleting temporary access key...")
                    iam_client = bootstrap_session.client('iam')
                    iam_client.delete_access_key(
                        UserName=base_username,
                        AccessKeyId=base_access_key['AccessKeyId']
                    )
                    print(f"  ✓ Temporary access key deleted")

                    # Step 4: Store the credentials
                    update_profile_credentials(base_username, temp_creds, base_username)
                    print(f"✓ Credentials generated for '{base_username}'")

                except Exception as cred_error:
                    print(f"⚠ Warning: Could not generate credentials for '{base_username}': {cred_error}", file=sys.stderr)
                    print(f"You can generate them later with: iam-sorry {base_username}", file=sys.stderr)
            else:
                print(f"✓ Base user '{base_username}' already exists")

                # Check if base user has credentials
                creds_file = get_aws_credentials_path()
                creds_config = read_aws_credentials(creds_file, auto_decrypt=True)

                if base_username not in creds_config:
                    print(f"  Base user has no credentials, generating them...")

                    try:
                        # Same credential generation logic as above
                        base_access_key = create_access_key_for_user("iam-sorry", base_username)
                        print(f"  ✓ Temporary access key created: {base_access_key['AccessKeyId'][:10]}***")

                        base_user_session = boto3.Session(
                            aws_access_key_id=base_access_key['AccessKeyId'],
                            aws_secret_access_key=base_access_key['SecretAccessKey']
                        )

                        import time
                        max_retries = 5
                        retry_delay = 2
                        temp_creds = None

                        for attempt in range(max_retries):
                            try:
                                base_sts = base_user_session.client('sts')
                                response = base_sts.get_session_token(DurationSeconds=36 * 3600)
                                temp_creds = response['Credentials']
                                print(f"  ✓ Session token generated")
                                break
                            except ClientError as e:
                                error_code = e.response['Error']['Code']
                                if error_code == 'InvalidClientTokenId' and attempt < max_retries - 1:
                                    print(f"  ⏳ Waiting {retry_delay}s for propagation (attempt {attempt + 1}/{max_retries})...")
                                    time.sleep(retry_delay)
                                    retry_delay *= 1.5
                                else:
                                    raise

                        if temp_creds:
                            iam_client = bootstrap_session.client('iam')
                            iam_client.delete_access_key(
                                UserName=base_username,
                                AccessKeyId=base_access_key['AccessKeyId']
                            )
                            print(f"  ✓ Temporary access key deleted")

                            update_profile_credentials(base_username, temp_creds, base_username)
                            print(f"  ✓ Credentials stored in profile '{base_username}'")
                    except Exception as cred_error:
                        print(f"  ⚠ Warning: Could not generate credentials: {cred_error}", file=sys.stderr)
    except Exception as e:
        print(f"⚠ Warning: Could not create base user: {e}", file=sys.stderr)
        print("You can create it later with: iam-sorry <base-username>", file=sys.stderr)

    print()
    print("=" * 70)
    print("✓ iam-sorry Profile Successfully Bootstrapped!")
    print("=" * 70)
    print()
    print("Profile created: [iam-sorry]")
    print("Credentials: ENCRYPTED (AES-256-GCM)")
    print("Location: ~/.aws/credentials")
    print(f"Region: {region}")
    print("Config: ~/.aws/config")
    print()
    print("=" * 70)
    print("CLEAN UP ENVIRONMENT VARIABLES")
    print("=" * 70)
    print()
    print("Remove temporary credentials from your environment:")
    print("  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN")
    print()
    print("=" * 70)
    print("NEXT STEPS")
    print("=" * 70)
    print()
    print("You can now use iam-sorry to manage your namespace:")
    print("  iam-sorry <username>        # Generate temporary credentials")
    print("  iam-sorry --eval            # Export credentials to environment")
    print("  iam-sorry --print-policy    # Show policy for your namespace")
    print()

    return True


def print_policy_setup_instructions(user_prefix):
    """Print standardized setup instructions for IAM policy creation."""
    print()
    print("# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("# TWO OPTIONS TO SET UP NAMESPACE MANAGEMENT")
    print("# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()
    print("# OPTION 1 (AUTOMATED): If you have IAM admin access")
    print("# ─────────────────────────────────────────────────────────────────────")
    print(
        f"#   $ iam-sorry --profile <admin-profile> --create-iam-sorry {user_prefix}-iam-sorry"
    )
    print("#")
    print("#   This will automatically:")
    print(f"#   • Create IAM user '{user_prefix}-iam-sorry' (manager)")
    print(f"#   • Attach inline policy 'iam-sorry-{user_prefix}'")
    print(f"#   • Policy allows creating users and roles in namespace ({user_prefix}, {user_prefix}-*)")
    print("#   • Create access key")
    print("#   • Display credentials in .aws/credentials format")
    print()
    print("# OPTION 2 (MANUAL): Request from AWS Administrator")
    print("# ─────────────────────────────────────────────────────────────────────")
    print()
    print("# 1. Send the policy printed above to your AWS administrator")
    print(f"#    Recommended username: '{user_prefix}-iam-sorry'")
    print(f"#    Policy name (inline): 'iam-sorry-{user_prefix}'")
    print()
    print("# 2. After the user is created, the administrator should:")
    print("#    a) Log in to AWS Console")
    print(f"#    b) Go to: IAM → Users → {user_prefix}-iam-sorry")
    print("#    c) Click: 'Add Permissions' → 'Create Inline Policy'")
    print("#    d) Select tab: 'JSON'")
    print("#    e) Clear the default policy and paste the JSON policy above")
    print(
        f"#    f) Click: 'Review Policy' → Name: 'iam-sorry-{user_prefix}' → 'Create Policy'"
    )
    print()
    print("# 3. Provide the new IAM user with:")
    print("#    - AWS Access Key ID")
    print("#    - AWS Secret Access Key")
    print()
    print("# 4. User adds credentials to ~/.aws/credentials:")
    print(f"#    [iam-sorry]")
    print(f"#    aws_access_key_id = AKIA...")
    print(f"#    aws_secret_access_key = ...")
    print()
    print("# 5. User encrypts the iam-sorry profile:")
    print(f"#    $ iam-sorry --encrypt")
    print()
    print("# 6. User can now manage their namespace:")
    print(f"#    $ iam-sorry {user_prefix}-admin")
    print(f"#    $ iam-sorry {user_prefix}-bedrock")
    print()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Pull temporary AWS credentials for an IAM user and update a profile",
        epilog="Examples:\n"
        "  iam-sorry jimmy                              # Generate credentials for user jimmy\n"
        "  iam-sorry --duration 12 admin                # 12-hour credentials\n"
        "  iam-sorry --print-admin-policy               # Full admin policy for namespace management\n"
        "  iam-sorry --print-policy                     # Minimal policy for namespace credential refresh",
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
        "--print-admin-policy",
        metavar="USER_PREFIX",
        nargs="?",
        const="",  # Empty string when --print-admin-policy is used without argument
        default=None,  # None when --print-admin-policy is not used at all
        help="Print the full IAM admin policy for managing users in a namespace. "
        "If USER_PREFIX is omitted, uses current Unix shell username as prefix. "
        "If specified, uses that prefix (e.g., --print-admin-policy iam)",
    )
    parser.add_argument(
        "--print-policy",
        metavar="USER_PREFIX",
        nargs="?",
        const="",  # Empty string when --print-policy is used without argument
        default=None,  # None when --print-policy is not used at all
        help="Print a minimal IAM policy for refreshing credentials in a namespace (no user creation). "
        "Allows refreshing credentials for all users with matching prefix. "
        "If USER_PREFIX is omitted, uses current Unix shell username as prefix. "
        "If specified, uses that prefix (e.g., --print-policy jimmy)",
    )
    parser.add_argument(
        "--print-lambda-policy",
        metavar="PROFILE",
        nargs="?",
        const="",  # Empty string when --print-lambda-policy is used without argument
        default=None,  # None when --print-lambda-policy is not used at all
        help="Print IAM policy for deploying Lambda-based web applications. "
        "Architecture: Lambda Function URL + CloudFront + Route53 + ACM (SSL). "
        "8-27%% cheaper than API Gateway. "
        "If PROFILE is omitted, uses 'default'. Extracts role ARN from profile config. "
        "Usage: iam-sorry --print-lambda-policy peterdir-zone1",
    )
    parser.add_argument(
        "--chown",
        metavar="OWNER",
        help="Delegate user management to another user (managers only). Creates user outside namespace (one-time only). "
        "Usage: ./iam-sorry --profile iam-sorry jimmy-bedrock --chown jimmy",
    )
    parser.add_argument(
        "--create-iam-sorry",
        metavar="USERNAME",
        help="Create a new iam-sorry manager user with inline policy (requires IAM admin permissions). "
        "Recommended username format: <prefix>-iam-sorry (e.g., dirk-iam-sorry). "
        "Usage: ./iam-sorry --profile admin-profile --create-iam-sorry dirk-iam-sorry",
    )
    parser.add_argument(
        "--fix-profiles",
        action="store_true",
        help="Check and fix AWS config profiles. For each profile in ~/.aws/credentials, "
        "ensure it exists in ~/.aws/config with region entry. Uses current default region. "
        "Shows fixed profiles and profiles in config but not in credentials.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Remove the [iam-sorry] section from both ~/.aws/credentials and ~/.aws/config. "
        "This resets iam-sorry to its initial state. Useful for re-bootstrapping or cleaning up.",
    )
    parser.add_argument(
        "--profiles",
        action="store_true",
        help="List all AWS profiles from ~/.aws/config (profile names only, without 'profile ' prefix).",
    )
    parser.add_argument(
        "profile_to_manage",
        nargs="?",
        default=None,
        help="Profile/user to manage. Behavior depends on the format:\n"
        "  Basic User (e.g., 'peter'): Refresh existing profile 'peter' or create new one. "
        "Creates an IAM user if needed and generates 36-hour temp credentials.\n"
        "  Suffixed User (e.g., 'peter-admin' or 'peter-bedrock'): Creates an IAM role 'iam-sorry-peter-admin' "
        "and profile entry with role assumption capability. Creates base user 'peter' if needed for role assumption.\n"
        "  Examples:\n"
        "    iam-sorry peter                  # Refresh/create 'peter' profile\n"
        "    iam-sorry peter-admin            # Create role-based profile 'peter-admin'\n"
        "    iam-sorry peter-bedrock          # Create role-based profile 'peter-bedrock'\n"
        "If omitted, defaults to the management profile (iam-sorry). "
        "Use --eval to inject credentials into environment.",
    )

    args = parser.parse_args()

    # AUTO-BOOTSTRAP: Try to auto-bootstrap iam-sorry profile from environment variables
    # Conditions:
    # - No command flags specified (no --print-*, --eval, --encrypt, etc.)
    # - No profile_to_manage positional argument
    # - AWS credentials in environment variables
    # - iam-sorry profile doesn't exist yet
    should_try_auto_bootstrap = (
        args.profile_to_manage is None
        and args.print_admin_policy is None
        and args.print_policy is None
        and args.print_lambda_policy is None
        and args.eval is None
        and not args.encrypt
        and not args.chown
        and not args.create_iam_sorry
        and not args.fix_profiles
        and not args.reset
        and not args.profiles
    )

    if should_try_auto_bootstrap:
        bootstrap_result = try_auto_bootstrap_iam_sorry()
        if bootstrap_result:
            sys.exit(0)
        elif bootstrap_result is False:
            # Bootstrap was attempted but failed - exit now
            print("\n⚠ Auto-bootstrap failed. Cannot proceed without valid credentials.", file=sys.stderr)
            print()
            print("To use iam-sorry, you need either:", file=sys.stderr)
            print("  1. An existing [iam-sorry] profile in ~/.aws/credentials", file=sys.stderr)
            print("  2. Valid AWS credentials exported in environment variables", file=sys.stderr)
            print()
            print("Example: Export credentials and bootstrap automatically", file=sys.stderr)
            print("  export AWS_ACCESS_KEY_ID='AKIAV44SMPYH...'", file=sys.stderr)
            print("  export AWS_SECRET_ACCESS_KEY='...'", file=sys.stderr)
            print("  export AWS_REGION='us-west-2'", file=sys.stderr)
            print("  iam-sorry", file=sys.stderr)
            sys.exit(1)
        else:
            # bootstrap_result is None - profile already exists, no bootstrap needed
            # User ran 'iam-sorry' with no arguments when profile already exists
            # This is ambiguous - show helpful message
            print()

            # Try to show which user the profile belongs to
            try:
                manager_profile = "iam-sorry"
                current_user = get_current_iam_user(manager_profile)
                print(f"The 'iam-sorry' profile already exists for user: {current_user}")
            except Exception:
                print("The 'iam-sorry' profile already exists.")

            # Check if base user exists and create if needed
            print()
            print("Checking if base user needs to be created...")

            try:
                import boto3
                manager_profile = "iam-sorry"
                bootstrap_session = create_session_with_profile(manager_profile)
                sts_client = bootstrap_session.client("sts")

                # Get the current user to determine the prefix
                identity = sts_client.get_caller_identity()
                arn = identity["Arn"]

                if ":user/" in arn:
                    username = arn.split(":user/")[1]
                    prefix = extract_username_prefix(username)
                    base_username = prefix

                    # Check if base user exists
                    if not verify_iam_user_exists(manager_profile, base_username):
                        print(f"Creating base user '{base_username}' for role assumption...")
                        create_iam_user(manager_profile, base_username)
                        print(f"✓ Base user '{base_username}' created")

                        # Generate credentials for the base user
                        print(f"Generating credentials for '{base_username}'...")

                        try:
                            # Create temporary access key for base user
                            print(f"  Creating temporary access key for '{base_username}'...")
                            base_access_key = create_access_key_for_user(manager_profile, base_username)
                            print(f"  ✓ Temporary access key created: {base_access_key['AccessKeyId'][:10]}***")

                            # Use base user credentials to call GetSessionToken AS the base user
                            base_user_session = boto3.Session(
                                aws_access_key_id=base_access_key['AccessKeyId'],
                                aws_secret_access_key=base_access_key['SecretAccessKey']
                            )

                            import time
                            max_retries = 5
                            retry_delay = 2
                            temp_creds = None

                            for attempt in range(max_retries):
                                try:
                                    base_sts = base_user_session.client('sts')
                                    response = base_sts.get_session_token(DurationSeconds=36 * 3600)
                                    temp_creds = response['Credentials']
                                    print(f"  ✓ Session token generated for '{base_username}'")
                                    break
                                except ClientError as e:
                                    error_code = e.response['Error']['Code']
                                    if error_code == 'InvalidClientTokenId' and attempt < max_retries - 1:
                                        print(f"  ⏳ Waiting {retry_delay}s for access key propagation (attempt {attempt + 1}/{max_retries})...")
                                        time.sleep(retry_delay)
                                        retry_delay *= 1.5
                                    else:
                                        raise

                            if temp_creds is None:
                                raise Exception("Failed to generate session token after multiple retries")

                            # Delete the temporary access key
                            print(f"  Deleting temporary access key...")
                            iam_client = bootstrap_session.client('iam')
                            iam_client.delete_access_key(
                                UserName=base_username,
                                AccessKeyId=base_access_key['AccessKeyId']
                            )
                            print(f"  ✓ Temporary access key deleted")

                            # Store the credentials
                            update_profile_credentials(base_username, temp_creds, base_username)
                            print(f"✓ Credentials generated for '{base_username}'")

                        except Exception as cred_error:
                            print(f"⚠ Warning: Could not generate credentials for '{base_username}': {cred_error}", file=sys.stderr)
                            print(f"You can generate them later with: iam-sorry {base_username}", file=sys.stderr)
                    else:
                        print(f"✓ Base user '{base_username}' already exists")

                        # Check if base user has credentials
                        creds_file = get_aws_credentials_path()
                        creds_config = read_aws_credentials(creds_file, auto_decrypt=True)

                        if base_username not in creds_config:
                            print(f"  Base user has no credentials, generating them...")

                            try:
                                base_access_key = create_access_key_for_user(manager_profile, base_username)
                                print(f"  ✓ Temporary access key created: {base_access_key['AccessKeyId'][:10]}***")

                                base_user_session = boto3.Session(
                                    aws_access_key_id=base_access_key['AccessKeyId'],
                                    aws_secret_access_key=base_access_key['SecretAccessKey']
                                )

                                import time
                                max_retries = 5
                                retry_delay = 2
                                temp_creds = None

                                for attempt in range(max_retries):
                                    try:
                                        base_sts = base_user_session.client('sts')
                                        response = base_sts.get_session_token(DurationSeconds=36 * 3600)
                                        temp_creds = response['Credentials']
                                        print(f"  ✓ Session token generated")
                                        break
                                    except ClientError as e:
                                        error_code = e.response['Error']['Code']
                                        if error_code == 'InvalidClientTokenId' and attempt < max_retries - 1:
                                            print(f"  ⏳ Waiting {retry_delay}s for propagation (attempt {attempt + 1}/{max_retries})...")
                                            time.sleep(retry_delay)
                                            retry_delay *= 1.5
                                        else:
                                            raise

                                if temp_creds:
                                    iam_client = bootstrap_session.client('iam')
                                    iam_client.delete_access_key(
                                        UserName=base_username,
                                        AccessKeyId=base_access_key['AccessKeyId']
                                    )
                                    print(f"  ✓ Temporary access key deleted")

                                    update_profile_credentials(base_username, temp_creds, base_username)
                                    print(f"  ✓ Credentials stored in profile '{base_username}'")
                            except Exception as cred_error:
                                print(f"  ⚠ Warning: Could not generate credentials: {cred_error}", file=sys.stderr)
            except Exception as e:
                print(f"⚠ Warning: Could not check/create base user: {e}", file=sys.stderr)

            print()
            print("=" * 70)
            print("MANAGE CREDENTIALS")
            print("=" * 70)
            print()
            print("Basic User Profile (generates temp credentials):")
            print(f"  iam-sorry {base_username}")
            print(f"    → Refreshes existing '{base_username}' profile or creates new one")
            print(f"    → Creates IAM user '{base_username}' if needed (must match namespace)")
            print("    → Generates 36-hour temporary credentials")
            print(f"    → Profile: ~/.aws/credentials [{base_username}]")
            print()
            print("Role-Based Profile (for role assumption):")
            print(f"  iam-sorry {base_username}-admin")
            print(f"    → Creates base user '{base_username}' if needed")
            print(f"    → Creates IAM role 'iam-sorry-{base_username}-admin'")
            print("    → Creates profile for role assumption")
            print(f"    → Profile: ~/.aws/config [profile {base_username}-admin] with role_arn + source_profile")
            print()
            print(f"  iam-sorry {base_username}-bedrock        # Same pattern for different roles/services")
            print()
            print("=" * 70)
            print("OTHER OPERATIONS")
            print("=" * 70)
            print()
            print("  iam-sorry --eval               # Export credentials for [default] profile")
            # Align comments by padding to consistent column (# at position 33)
            eval_cmd = f"  iam-sorry --eval {base_username}"
            padding = " " * (33 - len(eval_cmd))
            print(f"{eval_cmd}{padding}# Export credentials for '{base_username}' profile")
            print("  iam-sorry --print-policy       # Show policy for your namespace")
            print("  iam-sorry --encrypt            # Encrypt iam-sorry profile credentials")
            print("  iam-sorry --reset              # Remove iam-sorry profile (for re-bootstrap)")
            print("  iam-sorry --fix-profiles       # Ensure all profiles in config match credentials")
            print()
            sys.exit(0)

    # Handle --print-admin-policy flag
    if args.print_admin_policy is not None:
        import pwd

        # Determine which profile to use for getting user/account info
        # Default to iam-sorry if not specified
        manager_profile = args.profile or os.environ.get("AWS_PROFILE") or "iam-sorry"

        # Determine user prefix for policy
        if args.print_admin_policy == "":
            # --print-admin-policy was specified without an argument
            # Use the current Unix shell username as the prefix
            try:
                unix_username = pwd.getpwuid(os.getuid()).pw_name
                user_prefix = unix_username
            except (KeyError, OSError):
                print(
                    "Error: Could not determine current Unix username",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            # --print-admin-policy was specified with an argument
            user_prefix = args.print_admin_policy

        # Validate user prefix format (alphanumeric and hyphens only)
        import re

        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", user_prefix):
            print(
                f"Error: Invalid prefix format '{user_prefix}'",
                file=sys.stderr,
            )
            print(
                "Prefix must contain only alphanumeric characters and hyphens",
                file=sys.stderr,
            )
            print(
                "Examples: 'dirk', 'alice', 'bob-team'",
                file=sys.stderr,
            )
            sys.exit(1)

        try:
            account_id = get_aws_account_id(manager_profile)
            policy = generate_usermanager_policy(manager_profile, user_prefix)

            # Print policy header
            print(f"# IAM Policy for Full Namespace Management")
            print(f"# Namespace prefix: {user_prefix}")
            print(f"# Account: {account_id}")
            print()
            print("# PERMISSIONS PROVIDED BY THIS POLICY:")
            print("#   • Create IAM users and roles in namespace")
            print("#   • Manage trust policies for roles (who can assume)")
            print("#   • Manage access keys for namespace users")
            print("#   • Generate temporary credentials (GetSessionToken)")
            print("#   • Tag users and roles (cannot remove tags)")
            print("#   • Delegate users to other managers (--chown)")
            print("#   • Read IAM user and role information")
            print()
            print("# PERMISSIONS NOT GRANTED (AWS Admin only):")
            print("#   • Attach permission policies to roles (authorization)")
            print("#   • Attach permission policies to users")
            print()
            print(json.dumps(policy, indent=2))

            # Print setup instructions
            print_policy_setup_instructions(user_prefix)
            sys.exit(0)
        except Exception as e:
            print(f"Error: Failed to generate policy: {e}", file=sys.stderr)
            sys.exit(1)

    # Handle --print-policy flag (simpler refresh-only policy)
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
            except (KeyError, OSError):
                print(
                    "Error: Could not determine current Unix username",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            # --print-policy was specified with an argument
            user_prefix = args.print_policy

        # Validate user prefix format (alphanumeric and hyphens only)
        import re

        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", user_prefix):
            print(
                f"Error: Invalid prefix format '{user_prefix}'",
                file=sys.stderr,
            )
            print(
                "Prefix must contain only alphanumeric characters and hyphens",
                file=sys.stderr,
            )
            print(
                "Examples: 'dirk', 'alice', 'bob-team'",
                file=sys.stderr,
            )
            sys.exit(1)

        try:
            account_id = get_aws_account_id(manager_profile)
            policy = generate_refresh_only_policy(manager_profile, user_prefix)

            # Print policy header
            print(f"# IAM Policy for Credential Refresh Only")
            print(f"# Namespace prefix: {user_prefix}")
            print(f"# Account: {account_id}")
            print()
            print("# PERMISSIONS PROVIDED BY THIS POLICY:")
            print("#   • Refresh temporary credentials for namespace users")
            print("#   • Read user information (GetUser, ListAccessKeys)")
            print("#   • Check identity (GetCallerIdentity)")
            print()
            print("# RESTRICTIONS (cannot do the following):")
            print("#   • Create new IAM users")
            print("#   • Manage access keys")
            print("#   • Tag users or modify IAM policies")
            print("#   • Manage users outside namespace")
            print()
            print(json.dumps(policy, indent=2))

            # Print setup instructions
            print_policy_setup_instructions(user_prefix)
            sys.exit(0)
        except Exception as e:
            print(f"Error: Failed to generate policy: {e}", file=sys.stderr)
            sys.exit(1)

    # Handle --print-lambda-policy flag
    if args.print_lambda_policy is not None:
        # Determine which profile to use
        if args.print_lambda_policy == "":
            # --print-lambda-policy was specified without an argument
            profile_name = "default"
        else:
            # --print-lambda-policy was specified with an explicit profile name
            profile_name = args.print_lambda_policy

        print(f"# Generating Lambda deployment policy for profile: {profile_name}")
        print()

        # Read the config file to get role ARN
        try:
            config_file = get_aws_config_path()
            config_parser = configparser.ConfigParser()
            config_parser.optionxform = str

            if not os.path.exists(config_file):
                print(f"Error: Config file not found: {config_file}", file=sys.stderr)
                print("Run 'iam-sorry <profile>' first to create the profile.", file=sys.stderr)
                sys.exit(1)

            config_parser.read(config_file)
            profile_section = f"profile {profile_name}" if profile_name != "default" else "default"

            if profile_section not in config_parser:
                print(f"Error: Profile '{profile_name}' not found in config file", file=sys.stderr)
                print(f"Available profiles:", file=sys.stderr)
                for section in config_parser.sections():
                    if section.startswith("profile "):
                        print(f"  - {section.replace('profile ', '')}", file=sys.stderr)
                sys.exit(1)

            role_arn = config_parser[profile_section].get("role_arn")
            if not role_arn:
                print(f"Error: Profile '{profile_name}' is not a role profile (no role_arn)", file=sys.stderr)
                print("This command only works with role profiles.", file=sys.stderr)
                print(f"Create a role profile with: iam-sorry <prefix>-<role-name>", file=sys.stderr)
                sys.exit(1)

            # Extract role name and account from ARN
            # ARN format: arn:aws:iam::ACCOUNT:role/ROLE_NAME
            role_name = role_arn.split("/")[-1]
            account_id = role_arn.split(":")[4]

            # Extract namespace prefix from role name
            # Role name format: iam-sorry-{prefix}-{role-suffix}
            # Example: iam-sorry-sue-lambda → prefix is "sue"
            prefix = None
            if role_name.startswith("iam-sorry-"):
                # Remove "iam-sorry-" prefix
                remainder = role_name[10:]  # "sue-lambda"
                # Extract first part before next hyphen
                if "-" in remainder:
                    prefix = remainder.split("-")[0]  # "sue"
                else:
                    prefix = remainder  # Edge case: just "iam-sorry-sue"

            print(f"# Role ARN: {role_arn}")
            print(f"# Role Name: {role_name}")
            print(f"# Account: {account_id}")
            if prefix:
                print(f"# Namespace Prefix: {prefix}")
            print()

        except Exception as e:
            print(f"Error: Failed to read profile configuration: {e}", file=sys.stderr)
            sys.exit(1)

        # Generate comprehensive Lambda deployment policy
        lambda_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "LambdaFunctionManagement",
                    "Effect": "Allow",
                    "Action": [
                        "lambda:CreateFunction",
                        "lambda:DeleteFunction",
                        "lambda:UpdateFunctionCode",
                        "lambda:UpdateFunctionConfiguration",
                        "lambda:GetFunction",
                        "lambda:GetFunctionConfiguration",
                        "lambda:ListVersionsByFunction",
                        "lambda:PublishVersion",
                        "lambda:CreateAlias",
                        "lambda:UpdateAlias",
                        "lambda:DeleteAlias",
                        "lambda:GetAlias",
                        "lambda:ListAliases",
                        "lambda:AddPermission",
                        "lambda:RemovePermission",
                        "lambda:GetPolicy",
                        "lambda:PutFunctionConcurrency",
                        "lambda:DeleteFunctionConcurrency",
                        "lambda:TagResource",
                        "lambda:UntagResource",
                        "lambda:ListTags",
                        "lambda:CreateFunctionUrlConfig",
                        "lambda:DeleteFunctionUrlConfig",
                        "lambda:UpdateFunctionUrlConfig",
                        "lambda:GetFunctionUrlConfig"
                    ],
                    "Resource": f"arn:aws:lambda:*:{account_id}:function:*"
                },
                {
                    "Sid": "LambdaServiceOperations",
                    "Effect": "Allow",
                    "Action": [
                        "lambda:ListFunctions"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "LambdaLayerManagement",
                    "Effect": "Allow",
                    "Action": [
                        "lambda:PublishLayerVersion",
                        "lambda:DeleteLayerVersion",
                        "lambda:GetLayerVersion",
                        "lambda:ListLayerVersions",
                        "lambda:ListLayers"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "CloudFrontManagement",
                    "Effect": "Allow",
                    "Action": [
                        "cloudfront:CreateDistribution",
                        "cloudfront:UpdateDistribution",
                        "cloudfront:DeleteDistribution",
                        "cloudfront:GetDistribution",
                        "cloudfront:GetDistributionConfig",
                        "cloudfront:ListDistributions",
                        "cloudfront:CreateInvalidation",
                        "cloudfront:GetInvalidation",
                        "cloudfront:ListInvalidations",
                        "cloudfront:TagResource",
                        "cloudfront:UntagResource",
                        "cloudfront:ListTagsForResource",
                        "cloudfront:CreateOriginAccessControl",
                        "cloudfront:GetOriginAccessControl",
                        "cloudfront:DeleteOriginAccessControl",
                        "cloudfront:UpdateOriginAccessControl"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "ACMCertificateManagement",
                    "Effect": "Allow",
                    "Action": [
                        "acm:RequestCertificate",
                        "acm:DescribeCertificate",
                        "acm:ListCertificates",
                        "acm:GetCertificate",
                        "acm:DeleteCertificate",
                        "acm:AddTagsToCertificate",
                        "acm:ListTagsForCertificate",
                        "acm:RemoveTagsFromCertificate"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "Route53Management",
                    "Effect": "Allow",
                    "Action": [
                        "route53:ListHostedZones",
                        "route53:GetHostedZone",
                        "route53:ListResourceRecordSets",
                        "route53:ChangeResourceRecordSets",
                        "route53:GetChange"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "IAMPassRoleForLambda",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": f"arn:aws:iam::{account_id}:role/*",
                    "Condition": {
                        "StringEquals": {
                            "iam:PassedToService": "lambda.amazonaws.com"
                        }
                    }
                },
                {
                    "Sid": "IAMReadOnlyForRoles",
                    "Effect": "Allow",
                    "Action": [
                        "iam:GetRole",
                        "iam:ListRoles",
                        "iam:ListRolePolicies",
                        "iam:GetRolePolicy"
                    ],
                    "Resource": "*"
                }
            ]
        }

        # Add S3 and DynamoDB statements if namespace prefix is available
        if prefix:
            # S3 Bucket Operations (namespace-restricted)
            lambda_policy["Statement"].append({
                "Sid": "S3BucketManagement",
                "Effect": "Allow",
                "Action": [
                    "s3:CreateBucket",
                    "s3:DeleteBucket",
                    "s3:ListBucket",
                    "s3:GetBucketLocation",
                    "s3:GetBucketVersioning",
                    "s3:PutBucketVersioning",
                    "s3:GetBucketCORS",
                    "s3:PutBucketCORS",
                    "s3:GetBucketWebsite",
                    "s3:PutBucketWebsite",
                    "s3:DeleteBucketWebsite",
                    "s3:GetBucketPolicy",
                    "s3:PutBucketPolicy",
                    "s3:DeleteBucketPolicy",
                    "s3:GetBucketTagging",
                    "s3:PutBucketTagging"
                ],
                "Resource": f"arn:aws:s3:::{prefix}-*"
            })

            # S3 Object Operations (namespace-restricted)
            lambda_policy["Statement"].append({
                "Sid": "S3ObjectManagement",
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:GetObjectVersion",
                    "s3:DeleteObjectVersion",
                    "s3:GetObjectAttributes",
                    "s3:PutObjectAcl",
                    "s3:GetObjectAcl",
                    "s3:ListMultipartUploadParts",
                    "s3:AbortMultipartUpload"
                ],
                "Resource": f"arn:aws:s3:::{prefix}-*/*"
            })

            # S3 Service-level Operations (read-only, needed for AWS CLI/SDK)
            lambda_policy["Statement"].append({
                "Sid": "S3ServiceOperations",
                "Effect": "Allow",
                "Action": [
                    "s3:ListAllMyBuckets",
                    "s3:GetBucketLocation"
                ],
                "Resource": "*"
            })

            # DynamoDB Table Operations (namespace-restricted)
            lambda_policy["Statement"].append({
                "Sid": "DynamoDBTableManagement",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:CreateTable",
                    "dynamodb:DeleteTable",
                    "dynamodb:DescribeTable",
                    "dynamodb:UpdateTable",
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                    "dynamodb:DeleteItem",
                    "dynamodb:Query",
                    "dynamodb:Scan",
                    "dynamodb:BatchGetItem",
                    "dynamodb:BatchWriteItem",
                    "dynamodb:ConditionCheckItem",
                    "dynamodb:DescribeTimeToLive",
                    "dynamodb:UpdateTimeToLive",
                    "dynamodb:TagResource",
                    "dynamodb:UntagResource",
                    "dynamodb:ListTagsOfResource"
                ],
                "Resource": [
                    f"arn:aws:dynamodb:*:{account_id}:table/{prefix}-*",
                    f"arn:aws:dynamodb:*:{account_id}:table/{prefix}-*/index/*",
                    f"arn:aws:dynamodb:*:{account_id}:table/{prefix}-*/stream/*"
                ]
            })

            # DynamoDB Service-level Operations (read-only, needed for discovery)
            lambda_policy["Statement"].append({
                "Sid": "DynamoDBServiceOperations",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:ListTables",
                    "dynamodb:DescribeLimits"
                ],
                "Resource": "*"
            })

        print("# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("# LAMBDA WEB APPLICATION DEPLOYMENT POLICY")
        print("# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print()
        print("# ARCHITECTURE: Lambda Function URL + CloudFront + Route53 + ACM")
        print("#   Cost-effective alternative to API Gateway (8-27% cheaper)")
        print()
        print("# SERVICES COVERED:")
        print("#   • Lambda: Function URL, layers, concurrency, permissions")
        print("#   • CloudFront: CDN distribution, invalidation, origin access")
        print("#   • Route53: DNS zones, record sets")
        print("#   • ACM: SSL/TLS certificates (HTTPS)")
        print("#   • IAM: Pass role to Lambda (execution roles)")
        if prefix:
            print(f"#   • S3: Buckets and objects with namespace prefix '{prefix}-*'")
            print(f"#   • DynamoDB: Tables with namespace prefix '{prefix}-*'")
        print()
        print("# USE CASES:")
        print("#   ✓ Deploy Lambda functions with Function URLs")
        print("#   ✓ Set up CloudFront distribution for custom domain")
        print("#   ✓ Configure Route53 DNS records")
        print("#   ✓ Request and manage SSL certificates")
        if prefix:
            print(f"#   ✓ Store data in S3 buckets (must start with '{prefix}-')")
            print(f"#   ✓ Use DynamoDB tables (must start with '{prefix}-')")
        print()
        if prefix:
            print("# NAMESPACE SECURITY:")
            print(f"#   This policy enforces namespace separation using prefix '{prefix}-'")
            print(f"#   • S3 buckets must be named: {prefix}-mybucket, {prefix}-uploads, etc.")
            print(f"#   • DynamoDB tables must be named: {prefix}-users, {prefix}-sessions, etc.")
            print(f"#   • This prevents accidental access to other users' resources")
            print()
        print(json.dumps(lambda_policy, indent=2))
        print()
        print("# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print("# HOW TO APPLY THIS POLICY")
        print("# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print()
        print(f"# Send this JSON policy to your AWS administrator.")
        print(f"#")
        print(f"# STEP 1: Save JSON above to file")
        print(f"#   cat > lambda-deploy-policy.json")
        print(f"#   (paste JSON, then press Ctrl-D)")
        print(f"#")
        print(f"# STEP 2: Attach policy to role (copy command below)")
        print()
        print(f"aws --profile <admin-profile> iam put-role-policy \\")
        print(f"  --role-name {role_name} \\")
        print(f"  --policy-name lambda-deployment \\")
        print(f"  --policy-document file://lambda-deploy-policy.json")
        print()
        print(f"# STEP 3: Test with")
        print()
        print(f"AWS_PROFILE={profile_name} aws lambda list-functions")
        print()

        sys.exit(0)

    # Handle --create-iam-sorry flag
    if args.create_iam_sorry:
        import re

        username = args.create_iam_sorry

        # Validate username format (IAM username requirements)
        if not re.match(r"^[a-zA-Z0-9+=,.@_-]{1,64}$", username):
            print(
                f"Error: Invalid IAM username format '{username}'",
                file=sys.stderr,
            )
            print(
                "IAM usernames must be 1-64 characters: a-z, A-Z, 0-9, +, =, ,, ., @, _, -",
                file=sys.stderr,
            )
            sys.exit(1)

        # Determine which profile to use (must have IAM admin permissions)
        admin_profile = args.profile or os.environ.get("AWS_PROFILE")

        if not admin_profile:
            print(
                "Error: --create-iam-sorry requires a profile with IAM admin permissions",
                file=sys.stderr,
            )
            print(
                "Usage: iam-sorry --profile <admin-profile> --create-iam-sorry <username>",
                file=sys.stderr,
            )
            sys.exit(1)

        # CRITICAL: Reject if using iam-sorry profile (insufficient permissions)
        if admin_profile == "iam-sorry":
            print(
                "Error: Cannot use 'iam-sorry' profile to create manager users",
                file=sys.stderr,
            )
            print(
                "The 'iam-sorry' profile has restricted permissions and cannot create users or attach policies.",
                file=sys.stderr,
            )
            print(
                "Please use a profile with full IAM admin permissions (e.g., --profile admin-profile).",
                file=sys.stderr,
            )
            sys.exit(1)

        # CRITICAL: iam-sorry manager users MUST have a hyphen (namespace requirement)
        if "-" not in username:
            print(
                f"Error: Invalid iam-sorry manager username '{username}'",
                file=sys.stderr,
            )
            print(
                "Manager usernames MUST contain a hyphen to establish namespace prefix.",
                file=sys.stderr,
            )
            print()
            print("Why this is required:", file=sys.stderr)
            print("  • The prefix (before first hyphen) defines the namespace", file=sys.stderr)
            print("  • Managers can only create users matching their prefix", file=sys.stderr)
            print("  • Without a hyphen, the prefix would be the entire username", file=sys.stderr)
            print("  • This would allow creating themselves (security violation)", file=sys.stderr)
            print()
            print("Examples of VALID manager usernames:", file=sys.stderr)
            print("  ✓ jimmy-iam-sorry  (prefix: jimmy)", file=sys.stderr)
            print("  ✓ alice-manager    (prefix: alice)", file=sys.stderr)
            print("  ✓ bob-admin        (prefix: bob)", file=sys.stderr)
            print()
            print("Examples of INVALID manager usernames:", file=sys.stderr)
            print("  ✗ jimmy            (no hyphen - would conflict with base user)", file=sys.stderr)
            print("  ✗ admin            (no hyphen - cannot establish namespace)", file=sys.stderr)
            print()
            print(f"Suggested fix: Use '{username}-iam-sorry' instead", file=sys.stderr)
            sys.exit(1)

        # Extract prefix from username
        prefix = extract_username_prefix(username)

        # Show which admin user is performing this operation
        try:
            admin_user = get_current_iam_user(admin_profile)
            print(f"Using admin profile: {admin_profile}")
            print(f"Admin IAM user: {admin_user}")
            print()
        except Exception as e:
            print(f"Warning: Could not determine admin user: {e}", file=sys.stderr)
            print()

        print(f"Creating iam-sorry manager user: {username}")
        print(f"Extracted prefix: {prefix}")
        print(f"Policy name: iam-sorry-{prefix}")
        print()

        try:
            # Step 1: Check if user already exists
            if verify_iam_user_exists(admin_profile, username):
                print(
                    f"Error: IAM user '{username}' already exists",
                    file=sys.stderr,
                )
                print(
                    "Cannot create a user that already exists. Choose a different username.",
                    file=sys.stderr,
                )
                sys.exit(1)

            # Step 2: Create the IAM user
            print(f"Creating IAM user '{username}'...")
            user_info = create_iam_user(admin_profile, username)
            if user_info is None:
                # Shouldn't happen since we checked above, but handle gracefully
                print(
                    f"Error: User '{username}' already exists",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(f"✓ IAM user '{username}' created")

            # Step 3: Generate the iam-sorry policy for this prefix
            print(f"Generating iam-sorry policy for prefix '{prefix}'...")
            policy_document = generate_usermanager_policy(admin_profile, prefix)
            policy_name = f"iam-sorry-{prefix}"

            # Step 4: Attach inline policy
            print(f"Attaching inline policy '{policy_name}'...")
            put_user_policy(admin_profile, username, policy_name, policy_document)
            print(f"✓ Inline policy '{policy_name}' attached")

            # Step 5: Generate permanent credentials for the new manager user
            # Manager users MUST have permanent credentials to function
            # They need continuous access for credential generation and delegation
            print(f"Generating permanent credentials for '{username}'...")

            # Step 5a: Create permanent access key for the new user
            access_key = create_access_key_for_user(admin_profile, username)
            print(f"  ✓ Access key created: {access_key['AccessKeyId'][:10]}***")
            print(f"✓ Permanent credentials generated (AKIA prefix)")
            print(f"  ⚠️ IMPORTANT: These are PERMANENT credentials - handle with care!")

            print()

            # Step 6: Display the policy JSON
            print("=" * 70)
            print("ATTACHED POLICY")
            print("=" * 70)
            print()
            print(f"Policy Name: {policy_name}")
            print(f"Attached to User: {username}")
            print()
            print(json.dumps(policy_document, indent=2))
            print()

            # Step 7: Instructions for end user
            print("=" * 70)
            print("SEND THESE INSTRUCTIONS TO THE END USER")
            print("=" * 70)
            print()
            print("⚠️ IMPORTANT: These are PERMANENT credentials")
            print()
            print("SECURITY NOTE:")
            print("  These credentials are ONLY safe if you follow the bootstrap steps below.")
            print("  When you bootstrap with iam-sorry, these credentials will be:")
            print("  1. Automatically disabled in AWS (status: Inactive)")
            print("  2. Replaced with new permanent credentials")
            print("  3. Encrypted at-rest in your local ~/.aws/credentials file")
            print()
            print("  If you do NOT bootstrap, these credentials remain active and should")
            print("  be revoked manually if compromised.")
            print()
            print("Follow these steps to bootstrap your iam-sorry profile:")
            print()
            print("1. Set up keychain with password-protected SSH key (if not already done):")
            print("   https://dirkpetersen.github.io/docs/shell/ssh/")
            print()
            print("2. Export the AWS credentials and region in terminal:")
            print(f"   export AWS_ACCESS_KEY_ID='{access_key['AccessKeyId']}'")
            print(f"   export AWS_SECRET_ACCESS_KEY='{access_key['SecretAccessKey']}'")
            print(f"   export AWS_REGION='us-west-2'  # Change if needed")
            print()
            print("3. Install or upgrade iam-sorry:")
            print("   python3 -m pip install --upgrade iam-sorry")
            print()
            print("4. Run iam-sorry to bootstrap your profile:")
            print("   iam-sorry")
            print()
            print("   This will:")
            print("   • Auto-detect your environment credentials")
            print("   • Automatically create new permanent credentials")
            print("   • Disable these temporary credentials (status: Inactive)")
            print("   • Create encrypted [iam-sorry] profile")
            print("   • Store new credentials in ~/.aws/credentials")
            print()
            print("5. Verify credentials are updated:")
            print("   iam-sorry --print-policy")
            print()
            print("6. Unset credentials from environment:")
            print("   unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_REGION")
            print()

            sys.exit(0)
        except Exception as e:
            print(f"Error: Failed to create iam-sorry manager user: {e}", file=sys.stderr)
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
                if not (
                    raw_access_key.startswith("__encrypted__:")
                    and raw_secret_key.startswith("__encrypted__:")
                ):
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
            if raw_access_key.startswith("__encrypted__:") and raw_secret_key.startswith(
                "__encrypted__:"
            ):
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

    # Handle --fix-profiles flag
    if args.fix_profiles:
        fix_aws_profiles()
        sys.exit(0)

    if args.reset:
        reset_iam_sorry_profile()
        sys.exit(0)

    if args.profiles:
        # List all AWS profiles from ~/.aws/config
        config_file = get_aws_config_path()
        if not os.path.exists(config_file):
            print("No AWS config file found at ~/.aws/config", file=sys.stderr)
            sys.exit(1)

        config_parser = configparser.ConfigParser()
        config_parser.optionxform = str
        try:
            config_parser.read(config_file)
        except Exception as e:
            print(f"Error reading config file: {e}", file=sys.stderr)
            sys.exit(1)

        # Extract profile names without "profile " prefix
        profiles = []
        for section in config_parser.sections():
            if section == "default":
                profiles.append("default")
            elif section.startswith("profile "):
                profile_name = section[8:]  # Remove "profile " prefix (8 chars)
                profiles.append(profile_name)

        if profiles:
            for profile in profiles:
                print(profile)
        else:
            print("No profiles found in ~/.aws/config", file=sys.stderr)

        sys.exit(0)

    # If no profile_to_manage is specified, default to the management profile
    if args.profile_to_manage is None:
        args.profile_to_manage = manager_profile

    # CRITICAL: Handle iam-sorry profile specially
    if args.profile_to_manage == manager_profile or args.profile_to_manage == "iam-sorry":
        profile_name = args.profile_to_manage

        # Check current state of profile
        raw_config = read_aws_credentials(creds_file, auto_decrypt=False)
        profile_exists = profile_name in raw_config

        should_bootstrap = False

        if profile_exists:
            profile = raw_config[profile_name]
            access_key = profile.get("aws_access_key_id", "")
            secret_key = profile.get("aws_secret_access_key", "")
            session_token = profile.get("aws_session_token", "")

            # Check if encrypted
            is_encrypted = (
                access_key.startswith("__encrypted__:") and
                secret_key.startswith("__encrypted__:")
            )

            # Check if temporary (has session token OR access key starts with ASIA)
            is_temporary = bool(session_token) or (access_key and access_key.startswith("ASIA"))

            # If permanent or encrypted, show error
            if is_encrypted or (not is_temporary and access_key):
                print(
                    f"Error: The '{profile_name}' profile contains permanent manager credentials",
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
            else:
                # Has temporary credentials - allow bootstrap
                should_bootstrap = True
        else:
            # Profile doesn't exist - allow bootstrap
            should_bootstrap = True

        if should_bootstrap:
            # Bootstrap from environment variables
            env_access_key = os.environ.get("AWS_ACCESS_KEY_ID")
            env_secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
            env_session_token = os.environ.get("AWS_SESSION_TOKEN")

            if not env_access_key or not env_secret_key:
                print(
                    f"Error: Cannot bootstrap '{profile_name}' profile",
                    file=sys.stderr,
                )
                print(
                    "No credentials found in environment variables.",
                    file=sys.stderr,
                )
                print(
                    "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY with permanent credentials.",
                    file=sys.stderr,
                )
                sys.exit(1)

            # Check if env credentials are temporary
            env_is_temporary = bool(env_session_token) or env_access_key.startswith("ASIA")

            final_access_key = env_access_key
            final_secret_key = env_secret_key

            if env_is_temporary:
                # Environment has temporary credentials
                # Try to create a new permanent access key using these temporary credentials
                print(f"Bootstrapping '{profile_name}' profile with temporary credentials...")
                print(f"Environment credentials: {env_access_key[:10]}*** (temporary)")
                print()
                print(f"Attempting to create new permanent access key...")

                try:
                    # Create a boto3 session with the environment credentials
                    import boto3
                    session = boto3.Session(
                        aws_access_key_id=env_access_key,
                        aws_secret_access_key=env_secret_key,
                        aws_session_token=env_session_token,
                    )

                    # Determine current IAM user
                    sts_client = session.client("sts")
                    identity = sts_client.get_caller_identity()
                    arn = identity["Arn"]

                    # Extract username from ARN
                    if ":user/" not in arn:
                        print(
                            f"Error: Cannot bootstrap with non-user credentials",
                            file=sys.stderr,
                        )
                        print(f"Current identity: {arn}", file=sys.stderr)
                        print(
                            "The iam-sorry profile requires IAM user credentials, not role/federated credentials.",
                            file=sys.stderr,
                        )
                        sys.exit(1)

                    current_username = arn.split(":user/")[1]
                    print(f"Current IAM user: {current_username}")

                    # Try to create a new access key for this user
                    iam_client = session.client("iam")
                    response = iam_client.create_access_key(UserName=current_username)
                    new_access_key = response["AccessKey"]

                    final_access_key = new_access_key["AccessKeyId"]
                    final_secret_key = new_access_key["SecretAccessKey"]

                    print(f"✓ New permanent access key created: {final_access_key[:10]}***")

                except ClientError as e:
                    error_code = e.response["Error"]["Code"]
                    if error_code == "AccessDenied":
                        print(
                            f"Error: Cannot create access key - permission denied",
                            file=sys.stderr,
                        )
                        print(
                            "\nYour temporary credentials do not have iam:CreateAccessKey permission.",
                            file=sys.stderr,
                        )
                        print(
                            "To bootstrap the iam-sorry profile, you need one of:",
                            file=sys.stderr,
                        )
                        print(
                            "  1. Permanent credentials (AKIA*) in environment variables",
                            file=sys.stderr,
                        )
                        print(
                            "  2. Temporary credentials with iam:CreateAccessKey permission",
                            file=sys.stderr,
                        )
                        sys.exit(1)
                    else:
                        print(
                            f"Error: Failed to create access key ({error_code})",
                            file=sys.stderr,
                        )
                        print(f"Details: {e}", file=sys.stderr)
                        sys.exit(1)
                except Exception as e:
                    print(f"Error: Failed to create access key", file=sys.stderr)
                    print(f"Details: {e}", file=sys.stderr)
                    sys.exit(1)
            else:
                # Environment has permanent credentials - use them directly
                print(f"Bootstrapping '{profile_name}' profile from environment variables...")
                print(f"Access Key ID: {env_access_key[:10]}*** (permanent)")

            # Write credentials to profile
            config = read_aws_credentials(creds_file, auto_decrypt=False)
            if profile_name not in config:
                config[profile_name] = {}

            config[profile_name]["aws_access_key_id"] = final_access_key
            config[profile_name]["aws_secret_access_key"] = final_secret_key
            # Don't include session token (these are permanent creds now)

            write_aws_credentials(creds_file, config)
            print(f"✓ Permanent credentials written to profile '{profile_name}'")

            # Encrypt the credentials
            print(f"Encrypting credentials with SSH key...")
            ssh_key_path = get_ssh_key_path()

            # Validate SSH key is password protected (same as --encrypt)
            is_protected = is_ssh_key_password_protected(ssh_key_path)
            if is_protected is False:
                print(
                    f"Error: SSH key '{ssh_key_path}' is not password protected.",
                    file=sys.stderr,
                )
                print(
                    "For security, only password-protected SSH keys can be used for encryption.",
                    file=sys.stderr,
                )
                print(f"Add a passphrase: ssh-keygen -p -f {ssh_key_path}", file=sys.stderr)
                sys.exit(1)
            elif is_protected is None:
                print(
                    f"Error: Could not verify if SSH key '{ssh_key_path}' is password protected.",
                    file=sys.stderr,
                )
                print("Please ensure it's a valid OPENSSH format key.", file=sys.stderr)
                sys.exit(1)

            # Encrypt
            encrypted_access_key = encrypt_credential(final_access_key, ssh_key_path)
            encrypted_secret_key = encrypt_credential(final_secret_key, ssh_key_path)

            # Update with encrypted credentials
            config[profile_name]["aws_access_key_id"] = encrypted_access_key
            config[profile_name]["aws_secret_access_key"] = encrypted_secret_key

            write_aws_credentials(creds_file, config)

            print(f"✓ Credentials encrypted with SSH key (passphrase required)")
            print()
            print(f"{'=' * 70}")
            print(f"✓ Profile '{profile_name}' successfully bootstrapped and encrypted")
            print(f"{'=' * 70}")
            print()
            print(f"You can now use iam-sorry to manage your namespace:")
            print(f"  iam-sorry <username>        # Generate temporary credentials")
            print(f"  iam-sorry --eval            # Export credentials to environment")
            print()

            sys.exit(0)

    # CRITICAL: Enforce encryption for iam-sorry profile (when actually using it)
    # The iam-sorry profile contains permanent manager credentials and MUST be encrypted
    if manager_profile == "iam-sorry":
        # Read WITHOUT auto-decrypt to check if credentials are encrypted
        raw_config = read_aws_credentials(creds_file, auto_decrypt=False)
        if manager_profile in raw_config:
            access_key = raw_config[manager_profile].get("aws_access_key_id", "")
            secret_key = raw_config[manager_profile].get("aws_secret_access_key", "")

            # Check if credentials are encrypted
            if not (
                access_key.startswith("__encrypted__:") and secret_key.startswith("__encrypted__:")
            ):
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

    # Check if this profile is a role (has source_profile in ~/.aws/config)
    source_profile = get_profile_source_profile(args.profile_to_manage)
    if source_profile:
        print(
            f"Error: Profile '{args.profile_to_manage}' is a role profile (source_profile: {source_profile})",
            file=sys.stderr,
        )
        print(
            f"To use this role, run iam-sorry with the source profile instead:",
            file=sys.stderr,
        )
        print(
            f"  iam-sorry {source_profile}",
            file=sys.stderr,
        )
        print(
            f"Then use the AWS CLI with the role profile:",
            file=sys.stderr,
        )
        print(
            f"  AWS_PROFILE={args.profile_to_manage} aws <command>",
            file=sys.stderr,
        )
        sys.exit(1)

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
        # Profile doesn't exist - determine if we're creating a role or user
        profile_name = args.profile_to_manage
        prefix = extract_username_prefix(profile_name)

        # If profile is the base user or manager, it's a user. Otherwise it's a role.
        if profile_name == prefix or profile_name == f"{prefix}-iam-sorry":
            print(f"Profile doesn't exist, treating '{profile_name}' as IAM username...")
            iam_username = profile_name
            is_role = False
        else:
            print(f"Profile doesn't exist, treating '{profile_name}' as IAM role...")
            iam_username = profile_name  # For validation
            is_role = True

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

            # Verify that the delegated owner exists as an IAM user
            if not verify_iam_user_exists(manager_profile, owner_username):
                print(
                    f"Error: Cannot delegate to '{owner_username}' - user does not exist in IAM",
                    file=sys.stderr,
                )
                print(
                    f"The owner must be an existing IAM user to delegate credentials to them.",
                    file=sys.stderr,
                )
                sys.exit(1)
        else:
            # Normal case: validate prefix matching for manager
            is_valid, reason = validate_username_prefix(manager_username, iam_username)
            if not is_valid:
                print(f"Error: {reason}", file=sys.stderr)
                sys.exit(1)

        # After prefix validation passes, check if user/role exists
        if is_role:
            # For roles, check if the role exists (not the user)
            role_name = f"iam-sorry-{profile_name}"
            user_exists = verify_iam_role_exists(manager_profile, role_name)
        else:
            # For users, check if the user exists
            user_exists = verify_iam_user_exists(manager_profile, iam_username)

        # If --chown and user EXISTS, check tags to prevent re-chown
        if args.chown and user_exists and not is_role:
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

        # Now create role or user if needed (prefix validation already passed)
        if not user_exists:
            if is_role:
                # Profile with suffix (e.g., peterdir-admin) - create as IAM role
                # Actual role name: iam-sorry-{profile_name}
                role_name = f"iam-sorry-{profile_name}"
                base_username = prefix

                # STEP 1: Ensure base user exists (with credentials for role assumption)
                base_user_exists = verify_iam_user_exists(manager_profile, base_username)
                if not base_user_exists:
                    print(f"Base user '{base_username}' does not exist, creating it first...")
                    try:
                        # Create the base IAM user
                        create_iam_user(manager_profile, base_username)
                        print(f"✓ IAM user '{base_username}' created")

                        # Generate temporary credentials for the base user (36h)
                        print(f"Generating temporary credentials for '{base_username}' (36 hours)...")
                        base_credentials = get_temp_credentials_for_user(
                            manager_profile, base_username, 36 * 3600
                        )
                        update_profile_credentials(base_username, base_credentials, base_username)
                        print(f"✓ Temporary credentials generated for '{base_username}'")

                    except ClientError as e:
                        error_code = e.response["Error"]["Code"]
                        print(f"Error: Failed to create base user '{base_username}' ({error_code})", file=sys.stderr)
                        print()
                        print("You need elevated IAM permissions for this action. Choose based on your needs:", file=sys.stderr)
                        print()
                        print(f"  1. To CREATE roles and users:  iam-sorry --print-admin-policy {profile_name}", file=sys.stderr)
                        print(f"     (Full namespace management - requires admin permissions)", file=sys.stderr)
                        print()
                        print(f"  2. To REFRESH credentials only: iam-sorry --print-policy {profile_name}", file=sys.stderr)
                        print(f"     (Minimal policy - only refresh existing users, cannot create)", file=sys.stderr)
                        print()
                        print("Send the policy output to your AWS administrator to grant permissions.", file=sys.stderr)
                        sys.exit(1)
                    except Exception as e:
                        print(f"Error: Failed to create base user '{base_username}': {str(e).split(':')[0]}", file=sys.stderr)
                        sys.exit(1)
                else:
                    print(f"✓ Base user '{base_username}' exists")

                # STEP 2: Create the role with retry logic for user propagation
                print(f"Creating IAM role '{role_name}'...")
                try:
                    import time

                    # Get account ID for trust policy
                    account_id = get_aws_account_id(manager_profile)

                    # Create trust policy allowing base user to assume this role
                    trust_policy = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": f"arn:aws:iam::{account_id}:user/{base_username}"
                                },
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringEquals": {
                                        "sts:ExternalId": profile_name
                                    }
                                }
                            }
                        ]
                    }

                    # Retry role creation if base user hasn't propagated yet
                    max_retries = 5
                    retry_delay = 2
                    role_created = False

                    for attempt in range(max_retries):
                        try:
                            create_iam_role(manager_profile, role_name, trust_policy,
                                            description=f"Role for {base_username} namespace")
                            role_created = True
                            print(f"✓ IAM role '{role_name}' created")
                            break
                        except ClientError as retry_error:
                            error_code = retry_error.response["Error"]["Code"]
                            if error_code == "MalformedPolicyDocument" and attempt < max_retries - 1:
                                # Base user hasn't propagated yet
                                print(f"⏳ Waiting {retry_delay}s for user '{base_username}' to propagate (attempt {attempt + 1}/{max_retries})...")
                                time.sleep(retry_delay)
                                retry_delay *= 1.5
                            else:
                                # Different error or final attempt
                                raise

                    if not role_created:
                        raise Exception("Failed to create role after multiple retry attempts")

                    # STEP 3: Write role profile configuration to ~/.aws/config
                    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
                    write_role_profile_config(
                        profile_name,
                        role_arn,
                        base_username,
                        profile_name  # external_id
                    )

                    # Store the base username for later use
                    iam_username = base_username
                except ClientError as e:
                    error_code = e.response["Error"]["Code"]
                    if error_code == "AccessDenied":
                        print(f"Error: Insufficient permissions to create role '{role_name}' ({error_code})", file=sys.stderr)
                        print()
                        print("You need elevated IAM permissions for this action. Choose based on your needs:", file=sys.stderr)
                        print()
                        print(f"  1. To CREATE roles and users:  iam-sorry --print-admin-policy {profile_name}", file=sys.stderr)
                        print(f"     (Full namespace management - requires admin permissions)", file=sys.stderr)
                        print()
                        print(f"  2. To REFRESH credentials only: iam-sorry --print-policy {profile_name}", file=sys.stderr)
                        print(f"     (Minimal policy - only refresh existing users, cannot create)", file=sys.stderr)
                        print()
                        print("Send the policy output to your AWS administrator to grant permissions.", file=sys.stderr)
                        sys.exit(1)
                    else:
                        print(f"Error: Failed to create role: {error_code}", file=sys.stderr)
                        sys.exit(1)
                except Exception as e:
                    error_msg = str(e)
                    print(f"Error: Failed to create role: {error_msg}", file=sys.stderr)

                    # Show more details for MalformedPolicyDocument
                    if "MalformedPolicyDocument" in error_msg:
                        print()
                        print("Trust policy that failed:", file=sys.stderr)
                        print(json.dumps(trust_policy, indent=2), file=sys.stderr)

                    print(f"Try: iam-sorry --print-admin-policy {prefix}", file=sys.stderr)
                    sys.exit(1)
            else:
                # Base user or manager user - create as IAM user
                print(f"Creating IAM user '{iam_username}'...")
                try:
                    create_iam_user(manager_profile, iam_username)
                    print(f"✓ IAM user '{iam_username}' created")
                except Exception as e:
                    print(f"Error: Failed to create IAM user: {str(e).split(':')[0]}", file=sys.stderr)
                    sys.exit(1)
        else:
            # User/role already exists
            if is_role:
                # Role exists, but config doesn't (we checked at the start)
                # Write the role config
                print(f"✓ IAM role '{role_name}' exists")

                # Ensure base user exists and has credentials
                base_username = prefix
                base_user_exists = verify_iam_user_exists(manager_profile, base_username)
                if not base_user_exists:
                    print(f"Error: Role exists but base user '{base_username}' does not exist", file=sys.stderr)
                    print(f"Create the base user first: iam-sorry {base_username}", file=sys.stderr)
                    sys.exit(1)

                # Write role config
                account_id = get_aws_account_id(manager_profile)
                role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
                write_role_profile_config(
                    profile_name,
                    role_arn,
                    base_username,
                    profile_name  # external_id
                )

                # Store the base username for later use
                iam_username = base_username
            else:
                print(f"IAM user verified: {iam_username}")

    # For profiles that already exist, we need to validate and check delegation
    # (The new user path already did this validation above)
    if args.profile_to_manage in creds_config:
        # Get manager username if we don't have it yet
        if "manager_username" not in locals():
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

            # Verify that the delegated owner exists as an IAM user
            if not verify_iam_user_exists(manager_profile, owner_username):
                print(
                    f"Error: Cannot delegate to '{owner_username}' - user does not exist in IAM",
                    file=sys.stderr,
                )
                print(
                    f"The owner must be an existing IAM user to delegate credentials to them.",
                    file=sys.stderr,
                )
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

    # For role profiles, we're done - config is written, exit
    # Roles are assumed by the base user, not used directly
    if 'is_role' in locals() and is_role:
        print()
        print(f"✓ Role profile '{args.profile_to_manage}' ready to use")
        print(f"Usage: AWS_PROFILE={args.profile_to_manage} aws <command>")
        sys.exit(0)

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
                    print(
                        f"Error: Failed to apply delegation tags after {max_retries} attempts: {e}",
                        file=sys.stderr,
                    )
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
