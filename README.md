# iam-sorry

[![PyPI](https://img.shields.io/pypi/v/iam-sorry.svg)](https://pypi.org/project/iam-sorry/)
[![Downloads](https://img.shields.io/pypi/dm/iam-sorry.svg)](https://pypi.org/project/iam-sorry/)
[![License](https://img.shields.io/github/license/dirkpetersen/iam-sorry)](https://raw.githubusercontent.com/dirkpetersen/iam-sorry/main/LICENSE)
[![Python Version](https://img.shields.io/pypi/pyversions/iam-sorry.svg)](https://pypi.org/project/iam-sorry/)
[![Build Status](https://github.com/dirkpetersen/iam-sorry/workflows/Publish%20to%20PyPI/badge.svg)](https://github.com/dirkpetersen/iam-sorry/actions)

A powerful Python CLI utility for managing temporary AWS credentials with optional SSH-key based encryption. Generate temporary IAM credentials, protect manager profiles with AES-256 encryption, and inject credentials into batch operations.

**Key Features**:
- ✅ Generate temporary AWS credentials (max 36 hours)
- ✅ SSH-key based AES-256 encryption for powerful profiles
- ✅ Automatic encryption validation (ED25519, password-protected)
- ✅ Batch operation support with environment injection
- ✅ Lazy decryption: credentials stay encrypted on disk
- ✅ Support for permanent and temporary profiles

## Quick Start

### Basic Usage

```bash
# 1. Store your management profile (one-time)
# Edit ~/.aws/credentials with your manager IAM credentials:
[iam-sorry]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
region = us-west-2

# 2. Encrypt the iam-sorry profile (one-time, optional)
iam-sorry --encrypt
# ✓ Manager profile 'iam-sorry' encrypted with SSH key

# 3. Create and generate temporary credentials for users in your namespace
iam-sorry iam-admin
# ✓ IAM user 'iam-admin' created
# ✓ Region: us-west-2
# ✓ Successfully updated profile 'iam-admin'
# ✓ Credentials expire at: 2025-10-26T12:00:00

# 4. Run batch operations with encrypted manager credentials
eval $(iam-sorry --eval iam-sorry)

for user in user1 user2 user3; do
  aws iam create-user --user-name $user
done

# 5. Cleanup
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

**Key Behavior:**
- Management profile defaults to `iam-sorry` (override with `--profile` or `AWS_PROFILE`)
- Users in your namespace (e.g., `iam-*` for manager `iam-admin`) are auto-created
- `~/.aws/config` is auto-populated with region from iam-sorry profile
- **CRITICAL**: The management profile is NEVER refreshed (permanent credentials must not be replaced)
- **CRITICAL**: The iam-sorry profile credentials MUST be encrypted (`iam-sorry --encrypt`)
- To use AWS, always generate a temporary profile: `./iam-sorry iam-bedrock`

## Vision & Architecture

### Use Case Coverage

This tool is pragmatically designed to handle three distinct credential management scenarios:

1. **Broad Temporary Access** (most common)
   - Short-lived credentials for batch operations
   - Limited to specific duration (1-36 hours)
   - Auto-expiration provides security boundary
   - Ideal for: HPC jobs, data processing, CI/CD pipelines

2. **Narrow Permanent Access** (low-risk services)
   - Long-lived credentials for specific services
   - Limited permissions per service role
   - Examples: bedrock, analytics, logging services
   - Ideal for: Service-to-service authentication

3. **Powerful IAM Access** (critical, encrypted)
   - Full IAM management capabilities
   - High privilege, sensitive credentials
   - Protected with SSH-key encryption
   - Ideal for: Infrastructure automation, user provisioning

### Current Implementation: SSH-Key Based (Pragmatic)

This interim solution leverages existing security infrastructure already in place at most organizations:

**Why SSH Keys?**
- Most HPC users, AI researchers, and developers already have password-protected SSH keys
- SSH keys commonly used for GitHub, GitLab, and other critical services
- SSH-agent caching eliminates repeated passphrase entry
- No additional credential management required
- Works in headless environments (HPC nodes, servers) without browser interaction

**Pragmatic Benefits:**
- Zero additional setup for users with existing SSH infrastructure
- Leverages familiar SSH passphrase protection
- Compatible with existing ssh-agent workflows
- No new password requirements
- Works offline and in air-gapped environments

### Future Vision: Department-Level Service (Long-Term)

The longer-term architectural vision is a centralized, auditable system:

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  User Authentication                                       │
│  ├─ Active Directory / LDAP                               │
│  ├─ Kerberos (krb5)                                       │
│  └─ Headless authentication (no browser required)         │
│         ↓                                                  │
│  Department IAM Service                                    │
│  ├─ Service runs with high-privilege IAM role             │
│  ├─ Receives delegated requests from users                │
│  ├─ All actions logged with user identity                 │
│  ├─ Audit trail for compliance                            │
│  └─ Permission model based on user group                  │
│         ↓                                                  │
│  AWS IAM Actions                                           │
│  ├─ create-user, delete-user                              │
│  ├─ attach-policy, detach-policy                          │
│  ├─ create-access-key, rotate-key                         │
│  └─ All traceable to user who initiated action            │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Benefits:
  ✓ Single point of IAM access (easier to audit)
  ✓ All actions logged with user identity
  ✓ Centralized permission model
  ✓ No credential distribution needed
  ✓ Reduces credential loss risk
  ✓ Prevents unauthorized IAM abuse
  ✓ Department-wide credential management
```

**Why This is Better for Production:**
- Single high-privilege credential (service identity) instead of many
- All IAM actions attributed to specific users
- Centralized audit trail for compliance
- Fine-grained permission delegation
- Kerberos authentication (works in headless environments)
- No credentials stored on individual machines

### Current vs. Future Tradeoffs

| Aspect | Current (SSH-Key) | Future (Service) |
|--------|-------------------|------------------|
| **Setup** | Per-user (self-service) | Per-department (IT-managed) |
| **Auth** | SSH passphrase | Kerberos (krb5) |
| **Credentials** | Distributed (each user) | Centralized (service only) |
| **Audit Trail** | Limited (per-machine logs) | Complete (all via service) |
| **Offline Access** | ✓ Yes | ✗ No (requires network) |
| **Headless Systems** | ✓ Excellent | ✓ Excellent (Kerberos capable) |
| **Security Model** | Good (encrypted at-rest) | Excellent (centralized) |
| **Compliance** | Medium (per-machine audit) | High (centralized logging) |

### Why SSH-Key Approach Now?

The interim SSH-key solution is chosen because:

1. **Existing Infrastructure**: Most users already have password-protected SSH keys
2. **Headless Compatibility**: Works on HPC nodes, servers without browser
3. **No Additional Setup**: Leverages existing ssh-agent workflows
4. **Quick Deployment**: Can be deployed immediately to self-sufficient users
5. **Low Friction**: Minimal learning curve for technical users
6. **Offline Capable**: Works in air-gapped environments

This allows departments to:
- Protect credentials immediately
- Give users self-service temporary credential generation
- Maintain audit logs at system level
- Plan for centralized service later without user disruption

### Target Users

**This Tool is Best For:**
- Self-sufficient technical users (DevOps, HPC, AI researchers)
- Organizations with existing SSH key infrastructure
- Teams using headless systems (no browser)
- Users needing on-demand temporary credentials
- Environments without centralized SSO/AD integration

**This Tool is NOT For:**
- Organizations with strong centralized IT governance
- Non-technical end users
- Systems requiring browser-based authentication
- Highly regulated environments (use service approach)

## Installation

### 1. Download

```bash
pip install iam-sorry
```

Or from source:

```bash
git clone https://github.com/dirkpetersen/iam-sorry
cd iam-sorry
pip install -e .
```

### 2. Prepare SSH Key

Your ED25519 SSH key must be password-protected:

```bash
# Check if your key is protected
ssh-keygen -l -f ~/.ssh/id_ed25519

# Add passphrase if not protected
ssh-keygen -p -f ~/.ssh/id_ed25519
```

### 3. Create iam-sorry Manager User

You have **two options** to create your iam-sorry manager user:

#### Option 1: Automated (Recommended) - If You Have IAM Admin Access

If you have a profile with full IAM admin permissions:

```bash
# Create the manager user with inline policy (one command!)
iam-sorry --profile iam-admin --create-iam-sorry dirk-iam-sorry

# This will:
# 1. Create IAM user 'dirk-iam-sorry'
# 2. Generate and attach inline policy 'iam-sorry-dirk'
# 3. Create access key
# 4. Display credentials in .aws/credentials format
```

**Output**:
```
======================================================================
CREDENTIALS (add to ~/.aws/credentials)
======================================================================

[iam-sorry]
aws_access_key_id = AKIA...
aws_secret_access_key = ...

======================================================================
IMPORTANT: Save these credentials now - they cannot be retrieved later!
======================================================================
```

**Recommended username format**: `<prefix>-iam-sorry` (e.g., `dirk-iam-sorry`, `alice-iam-sorry`)

#### Option 2: Manual - Request from Your AWS Administrator

If you don't have IAM admin access, request your administrator create the user:

```bash
# Generate the policy document
iam-sorry --print-policy dirk

# Send the output to your AWS administrator with these instructions:
# 1. Create IAM user 'dirk-iam-sorry' (or '<prefix>-iam-sorry')
# 2. Attach the policy as an inline policy named 'iam-sorry-dirk'
# 3. Create access key and provide credentials
```

Your administrator will provide you with:
- AWS Access Key ID
- AWS Secret Access Key

Add these to `~/.aws/credentials`:

```ini
[iam-sorry]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```

### 4. Encrypt iam-sorry Profile (Required)

```bash
# Encrypt your permanent manager credentials
iam-sorry --encrypt
# ✓ Manager profile 'iam-sorry' encrypted with SSH key
```

## Getting Started Workflow

Once you have your iam-sorry manager user set up, here's the complete workflow:

### Step 1: Initial Setup (One-Time)

Create your iam-sorry manager user (choose Option 1 or Option 2 above) and encrypt the profile.

### Step 2: Create and Manage Users

Use the iam-sorry profile to create users in your namespace with temporary credentials:

```bash
# Create new users (auto-creates IAM user if doesn't exist)
iam-sorry dirk-admin
# ✓ IAM user 'dirk-admin' created
# ✓ Successfully updated profile 'dirk-admin'
# ✓ Credentials expire at: 2025-10-26T12:00:00

iam-sorry dirk-bedrock
# ✓ IAM user 'dirk-bedrock' created
# ✓ Credentials expire at: 2025-10-26T12:00:00

# Refresh credentials for existing profiles (before they expire)
iam-sorry dirk-admin
# ✓ Successfully updated profile 'dirk-admin'
# ✓ Credentials expire at: 2025-10-27T12:00:00
```

**Important Notes**:
- **New users created by iam-sorry**: Have restrictive inline policy `iam-sorry-<prefix>` automatically attached, providing strong protection
- **Existing IAM users** (created before iam-sorry): Can refresh their credentials, but they don't have the restrictive inline policy and are not as well protected from future permission changes

### Step 3: Use Temporary Credentials

```bash
# Use the temporary credentials profile
export AWS_PROFILE=dirk-admin
aws s3 ls

# Or inject into environment for batch operations
eval $(iam-sorry --eval dirk-admin)
for bucket in bucket1 bucket2; do
  aws s3 sync ./data s3://$bucket/
done
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

## Usage Guide

### Encrypt Manager Profile

```bash
# One-time: Encrypt your powerful manager credentials
iam-sorry --profile usermanager --encrypt

# Verify encryption
iam-sorry --show-encrypted usermanager
```

**Result**:
```ini
[usermanager]
aws_access_key_id = __encrypted__:pdZLbbMlei28ZA0vhsT6gesOG6BLB...
aws_secret_access_key = __encrypted__:1vYfR8x2kjhsRR0vhsT6gesOG6B...
```

### Generate Temporary Credentials

```bash
# Generate temporary credentials for a specific IAM user
iam-sorry --profile usermanager admin

# Specify duration (1-36 hours, default: 36)
iam-sorry --profile usermanager --duration 12 admin

# Using environment variable instead of --profile
AWS_PROFILE=usermanager iam-sorry admin
```

**Output**:
```
✓ Successfully updated profile 'admin'
✓ IAM user: admin
✓ Credentials expire at: 2025-10-26T12:00:00
```

### Batch Operations with Encryption

```bash
# Inject encrypted manager credentials into environment
eval $(iam-sorry --eval usermanager)

# Now run batch IAM operations
for user in user1 user2 user3; do
  aws iam create-user --user-name $user
  aws iam attach-user-policy --user-name $user \
    --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
done

# Cleanup
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

### Batch Operations with Permanent Credentials

```bash
# For low-risk permanent credentials (bedrock service)
eval $(iam-sorry --eval bedrock)

# Run bulk operations
aws bedrock list-foundation-models
aws bedrock create-evaluation-job --config file://config.json

# Cleanup
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

### View Credentials

```bash
# View encrypted credentials (ciphertext, no decryption)
iam-sorry --show-encrypted usermanager

# View decrypted credentials (requires SSH passphrase)
iam-sorry --show-decrypted usermanager

# View plaintext credentials (for unencrypted profiles)
iam-sorry --show-decrypted bedrock
```

## Python API Usage

You can use iam-sorry as a Python library in your code, providing the same functionality as the `--eval` option but programmatically.

### Method 1: Direct boto3 Session (Recommended)

The simplest way - creates a boto3 session with auto-decrypted credentials:

```python
from iamsorry.core import create_session_with_profile

# Create a session with auto-decrypted credentials
session = create_session_with_profile('dirk-admin')

# Use with any AWS service
s3 = session.client('s3')
buckets = s3.list_buckets()

ec2 = session.resource('ec2')
instances = ec2.instances.all()

# Works with encrypted profiles too!
session = create_session_with_profile('iam-sorry')
iam = session.client('iam')
users = iam.list_users()
```

**Benefits**:
- ✅ Automatic credential decryption (SSH key required for encrypted profiles)
- ✅ No environment variable pollution
- ✅ Clean, Pythonic API
- ✅ Session-scoped credentials

### Method 2: Environment Variable Injection

Similar to `eval $(iam-sorry --eval profile)` but in Python:

```python
from iamsorry.core import read_aws_credentials, get_aws_credentials_path
import os

# Read and auto-decrypt credentials
creds_file = get_aws_credentials_path()
config = read_aws_credentials(creds_file, auto_decrypt=True)

# Get profile credentials
profile = config['dirk-admin']

# Inject into environment
os.environ['AWS_ACCESS_KEY_ID'] = profile['aws_access_key_id']
os.environ['AWS_SECRET_ACCESS_KEY'] = profile['aws_secret_access_key']
if 'aws_session_token' in profile:
    os.environ['AWS_SESSION_TOKEN'] = profile['aws_session_token']

# Now use with default boto3 client (uses environment)
import boto3
s3 = boto3.client('s3')
s3.list_buckets()

# Cleanup
del os.environ['AWS_ACCESS_KEY_ID']
del os.environ['AWS_SECRET_ACCESS_KEY']
if 'AWS_SESSION_TOKEN' in os.environ:
    del os.environ['AWS_SESSION_TOKEN']
```

**Benefits**:
- ✅ Compatible with libraries that read from environment
- ✅ Similar to CLI `--eval` workflow
- ⚠️ Requires manual cleanup

### Method 3: Get Credentials as Dictionary

For cases where you need raw credential values:

```python
from iamsorry.core import read_aws_credentials, get_aws_credentials_path

# Read credentials (auto-decrypt if encrypted)
creds_file = get_aws_credentials_path()
config = read_aws_credentials(creds_file, auto_decrypt=True)

# Get profile as dict
profile = config['dirk-admin']

# Access individual values
access_key = profile['aws_access_key_id']
secret_key = profile['aws_secret_access_key']
session_token = profile.get('aws_session_token', None)  # Optional
expiration = profile.get('expiration', None)  # Optional

# Use with custom AWS SDK wrappers or other tools
my_custom_aws_client(access_key, secret_key, session_token)
```

### Example: Using in a Python Script

```python
#!/usr/bin/env python3
"""
Backup S3 buckets using iam-sorry encrypted credentials.
"""

from iamsorry.core import create_session_with_profile
import sys

def backup_buckets(profile_name, destination):
    """Backup all S3 buckets to local destination."""
    try:
        # Create session with auto-decrypted credentials
        session = create_session_with_profile(profile_name)
        s3 = session.client('s3')

        # List all buckets
        response = s3.list_buckets()
        buckets = response['Buckets']

        print(f"Found {len(buckets)} buckets")

        for bucket in buckets:
            bucket_name = bucket['Name']
            print(f"Backing up: {bucket_name}")

            # Download bucket contents
            # ... your backup logic here ...

        print(f"✓ Backup complete: {len(buckets)} buckets")

    except Exception as e:
        print(f"Error: Failed to backup buckets: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    # Use encrypted iam-sorry profile credentials
    backup_buckets('iam-sorry', '/backup/s3')
```

### Example: Using in a Long-Running Service

```python
#!/usr/bin/env python3
"""
AWS monitoring service using iam-sorry credentials with auto-refresh.
"""

from iamsorry.core import (
    create_session_with_profile,
    credentials_need_refresh,
    read_aws_credentials,
    get_aws_credentials_path,
    get_temp_credentials_for_user,
    update_profile_credentials
)
import time

class AWSMonitor:
    def __init__(self, profile_name, manager_profile='iam-sorry'):
        self.profile_name = profile_name
        self.manager_profile = manager_profile
        self.session = None
        self._refresh_session()

    def _refresh_session(self):
        """Refresh credentials if needed and create new session."""
        creds_file = get_aws_credentials_path()
        config = read_aws_credentials(creds_file, auto_decrypt=True)

        if self.profile_name in config:
            profile = config[self.profile_name]
            needs_refresh, reason = credentials_need_refresh(profile, threshold_minutes=60)

            if needs_refresh:
                print(f"⚠ Refreshing credentials: {reason}")

                # Get IAM username
                iam_username = profile.get('credentials_owner')
                if iam_username:
                    # Refresh credentials (36 hours)
                    new_creds = get_temp_credentials_for_user(
                        self.manager_profile,
                        iam_username,
                        duration_seconds=36*3600
                    )
                    update_profile_credentials(
                        self.profile_name,
                        new_creds,
                        iam_username
                    )
                    print(f"✓ Credentials refreshed")

        # Create new session with (possibly refreshed) credentials
        self.session = create_session_with_profile(self.profile_name)

    def run(self):
        """Main monitoring loop."""
        while True:
            try:
                self._refresh_session()

                # Do monitoring work
                cloudwatch = self.session.client('cloudwatch')
                # ... your monitoring logic ...

                # Sleep 1 hour
                time.sleep(3600)

            except KeyboardInterrupt:
                print("Shutting down...")
                break
            except Exception as e:
                print(f"Error: {e}")
                time.sleep(60)  # Retry after 1 minute

if __name__ == '__main__':
    monitor = AWSMonitor('dirk-monitoring')
    monitor.run()
```

### Security Considerations for Python API

- **SSH Passphrase**: When using encrypted profiles, SSH key passphrase required (unless cached in ssh-agent)
- **Auto-Decryption**: `auto_decrypt=True` automatically decrypts credentials on read
- **In-Memory Only**: Decrypted credentials never written back to disk
- **Session Scoped**: Use Method 1 (direct session) to avoid environment pollution
- **Error Handling**: Catch exceptions for missing profiles, invalid credentials, expired sessions

## Command Reference

### Global Flags

```bash
--profile PROFILE           Manager profile (defaults to AWS_PROFILE env var)
--duration HOURS            Credential duration: 1-36 hours (default: 36)
```

### Main Commands

```bash
# Generate temporary credentials
iam-sorry --profile usermanager admin
iam-sorry --profile usermanager --duration 12 admin

# Encrypt manager profile (one-time)
iam-sorry --profile usermanager --encrypt

# Show encrypted credentials
iam-sorry --show-encrypted usermanager

# Show decrypted credentials
iam-sorry --show-decrypted usermanager

# Output environment export statements
iam-sorry --eval usermanager

# Refresh default profile (prompts for confirmation)
AWS_PROFILE=usermanager iam-sorry
```

### Manager Commands (Prefix-Based Access Control)

```bash
# Create and manage users in your namespace (auto-created if doesn't exist)
iam-sorry iam-bedrock           # Creates iam-bedrock, generates credentials
iam-sorry iam-analytics         # Creates iam-analytics, generates credentials

# The IAM user is created automatically if it doesn't exist
# Your namespace is based on your manager username prefix:
# - Manager 'iam-dirk' can create 'iam-bedrock', 'iam-analytics', etc.
# - Manager 'alice' can create 'alice-bedrock', 'alice-analytics', etc.

# Delegate user outside namespace to another owner (one-time only!)
iam-sorry jimmy-bedrock --chown jimmy    # Creates jimmy-bedrock, delegates to jimmy
```

### Print Policy

```bash
# Show the recommended IAM policy using current Unix username as prefix
iam-sorry --print-policy

# Show the recommended IAM policy for a specific prefix
iam-sorry --print-policy iam
iam-sorry --print-policy alice

# Policy is personalized with your account ID and the specified namespace prefix
# Output includes:
# 1. JSON policy document
# 2. Step-by-step instructions for AWS administrator
# 3. How to attach the policy to a new IAM user via AWS Console
```

**Next Steps**:
1. Copy the JSON policy
2. Send to your AWS administrator
3. Administrator creates a new IAM user (e.g., `dp-mgr`)
4. Administrator adds the policy as an inline policy via AWS Console
5. Receive Access Key ID and Secret Access Key
6. Configure credentials: `aws configure --profile iam-sorry`
7. Start using iam-sorry to manage your namespace users

## Manager Guide: User Delegation with --chown

### Use Case

Delegate user management to someone else (e.g., a student or teammate) without giving them manager credentials. The manager creates the user, configures it, then transfers ownership.

**Example Workflow**:
- Manager `dirk-admin` creates user `jimmy-bedrock` for student Jimmy
- Manager configures user via AWS console, adds to groups, sets permissions
- Manager runs: `./iam-sorry --profile iam-sorry jimmy-bedrock --chown jimmy`
- Student Jimmy can then manage their own credentials
- Manager loses write access (read-only viewing only)

### How It Works

**Step 1: Create and configure user**
```bash
# Manager creates user and profile
dirk-admin$ ./iam-sorry --profile iam-sorry jimmy-bedrock

# Manager configures via AWS console:
# - Add user to security groups
# - Add to project teams
# - Set resource tags
# - Configure MFA (optional)
```

**Step 2: Delegate to owner**
```bash
# Manager delegates ownership (ONE-TIME operation)
dirk-admin$ ./iam-sorry --profile iam-sorry jimmy-bedrock --chown jimmy

# Output:
# ⚠ Delegating user 'jimmy-bedrock' to 'jimmy' (one-time operation)
# ✓ Applied delegation tags:
#   - owner: jimmy
#   - delegated-by: dirk-admin
# ℹ User delegated to 'jimmy' - they can now manage their own credentials
```

**Step 3: Owner manages their own credentials**
```bash
# Jimmy (owner) can now refresh their own credentials
jimmy$ ./iam-sorry --profile iam-sorry jimmy-bedrock

# Auto-refresh is enabled for batch operations
jimmy$ eval $(./iam-sorry --eval jimmy-bedrock)
```

**Step 4: Original manager loses write access**
```bash
# Manager tries to refresh jimmy's credentials
dirk-admin$ ./iam-sorry --profile iam-sorry jimmy-bedrock

# Output:
# ⚠ User 'jimmy-bedrock' is delegated to 'jimmy'
# You can view this user but cannot manage credentials (read-only access)

# Manager can view user info in AWS console, but cannot:
# - Create new access keys
# - Delete access keys
# - Remove tags
# - Re-delegate the user
```

### Security Features

- ✅ **One-time only**: Cannot re-delegate a user that's already delegated
- ✅ **Permanent ownership**: Owner tag prevents manager from regaining access
- ✅ **Tag protection**: Manager cannot remove ownership tags
- ✅ **Read-only fallback**: Manager can still view delegated users
- ✅ **Audit trail**: `delegated-by` tag tracks original manager

### Requirements for Delegation

1. **Delegated owner must exist as IAM user** (verified by CLI before delegation)
2. **Delegated user must match owner's prefix** (e.g., cj-moin for owner cj)
3. **User must not have `owner` tag** (prevents re-delegation)
4. **Manager must have CreateUsersDelegation permission** (in generated IAM policy)

## Security Architecture

### Credential Types

| Profile | Type | Encryption | Risk | Usage |
|---------|------|-----------|------|-------|
| `usermanager` | Permanent | ✓ Encrypted | HIGH | Manager only |
| `bedrock` | Permanent | ✗ Plaintext | LOW | Direct service |
| `admin` | Temporary | ✗ Plaintext | LOW | Batch ops |

### Encryption Details

**Key Validation**:
- SSH key must be ED25519 (256-bit)
- SSH key must be password-protected
- Script validates automatically before encryption

**Encryption Process**:
```
SSH Private Key
    ↓ (HKDF-SHA256)
AES-256 Encryption Key (32 bytes)
    ↓
Credential Value + Random Nonce
    ↓ (AES-256-GCM)
__encrypted__:<base64>
    ↓
~/.aws/credentials (at-rest encrypted)
    ↓ (eval $(iam-sorry --eval usermanager))
Memory only (never on disk)
    ↓ (eval injects into environment)
AWS SDK access
```

### Security Guarantees

- ✅ **No unprotected keys**: SSH key must be password-protected
- ✅ **No plaintext on disk**: Manager credentials stored encrypted
- ✅ **No disk persistence**: Credentials only in memory during batch ops
- ✅ **Passphrase protected**: SSH passphrase required each time
- ✅ **Random nonces**: Different ciphertext each encryption
- ✅ **Lazy decryption**: Only decrypt when needed
- ✅ **Auto-cleanup**: Session tokens auto-expire (max 36 hours)

### Username Prefix-Based Access Control

`iam-sorry` enforces username prefix matching to prevent unauthorized user management. Managers can only create and manage users whose names match their namespace prefix. **Users within your namespace are automatically created if they don't exist.**

**How It Works**:

1. **Extract Prefix**: Everything before the first hyphen in the manager's username
   - `dirk-admin` → prefix is `dirk`
   - `alice-manager` → prefix is `alice`
   - `bob` (no hyphen) → prefix is `bob`

2. **Auto-Create Matching Users**: When you request credentials for a user:
   - Prefix is validated locally (fast)
   - If IAM user doesn't exist, it's created automatically
   - Temporary credentials are generated for the new user
   - `~/.aws/config` is populated with the region

3. **Allowed Operations**: Manager can only manage users that:
   - Start with `{prefix}-` (e.g., `dirk-admin` can manage `dirk-bedrock`, `dirk-analytics`)
   - OR are exactly the prefix (e.g., `dirk-admin` can manage `dirk`)
   - BUT not themselves (e.g., `dirk` cannot create `dirk`)

**Examples**:

```bash
# Manager: dirk-admin (prefix: dirk)
iam-sorry --profile iam-sorry dirk-bedrock    # ✓ Allowed
iam-sorry --profile iam-sorry dirk-analytics  # ✓ Allowed
iam-sorry --profile iam-sorry dirk            # ✓ Allowed
iam-sorry --profile iam-sorry alice           # ✗ Denied (wrong prefix)
iam-sorry --profile iam-sorry bob-service     # ✗ Denied (wrong prefix)

# Manager: alice (prefix: alice)
iam-sorry --profile iam-sorry alice-ml        # ✓ Allowed
iam-sorry --profile iam-sorry alice-data      # ✓ Allowed
iam-sorry --profile iam-sorry alice           # ✗ Denied (cannot create self)
```

**IAM Policy Enforcement**:

The generated IAM policy enforces namespace restrictions on credential management:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateUsers",
      "Effect": "Allow",
      "Action": ["iam:CreateUser"],
      "Resource": ["arn:aws:iam::123456789012:user/dirk", "arn:aws:iam::123456789012:user/dirk-*"]
    },
    {
      "Sid": "CreateUsersDelegation",
      "Effect": "Allow",
      "Action": ["iam:CreateUser"],
      "Resource": "arn:aws:iam::*:user/*"
    },
    {
      "Sid": "ManageUserCredentials",
      "Effect": "Allow",
      "Action": ["iam:CreateAccessKey", "iam:DeleteAccessKey", "..."],
      "Resource": ["arn:aws:iam::123456789012:user/dirk", "arn:aws:iam::123456789012:user/dirk-*"]
    },
    {
      "Sid": "ManageRestrictionTagsDelegation",
      "Effect": "Allow",
      "Action": ["iam:TagUser", "iam:ListUserTags"],
      "Resource": "arn:aws:iam::*:user/*"
    }
  ]
}
```

**Key Policy Design**:
- **CreateUsers**: Allows creating users in manager's namespace (dirk, dirk-*)
- **CreateUsersDelegation**: Allows creating ANY user (for --chown delegation)
- **ManageUserCredentials**: Restricted to namespace users only
- **ManageRestrictionTagsDelegation**: Allows tagging ANY user (needed for delegation)
- **CLI Validation**: Enforces prefix matching and validates owner existence
- **Permanent Restrictions**: Deny UntagUser on namespace users (tags cannot be removed)

**CLI Validation**:

The tool validates prefix matching before attempting AWS API calls (unless using --chown):

```bash
$ iam-sorry --profile iam-sorry alice
Error: Username 'alice' does not match required prefix.
Manager 'dirk-admin' (prefix: 'dirk') can only manage users named 'dirk' or 'dirk-*'

$ iam-sorry --profile iam-sorry cj-moin --chown cj
⚠ Delegating user 'cj-moin' to 'cj' (one-time operation)
✓ Successfully updated profile 'cj-moin'
```

**Security Benefits**:

- ✅ Managers can create users in other namespaces only with explicit --chown flag
- ✅ Credential management restricted to namespace (CLI + IAM policy enforcement)
- ✅ Delegation tags prevent accidental re-delegation
- ✅ Clear ownership: `dirk-admin` owns all `dirk-*` users
- ✅ Simplifies auditing: track which manager created and delegated which users

### Tagging Strategy for Permanent Restrictions

The IAM policy includes a one-time tagging approach to enforce permanent restrictions:

**How It Works**:

1. **Manager can ADD tags** (one-time setup):
   ```bash
   aws iam tag-user --user-name dirk-bedrock \
     --tags Key=manager-locked,Value=true Key=managed-by,Value=dirk-admin
   ```

2. **Manager can VIEW tags** (for audit trail):
   ```bash
   aws iam list-user-tags --user-name dirk-bedrock
   ```

3. **Manager CANNOT remove tags** (permanent lock):
   ```bash
   # This will be DENIED by the IAM policy
   aws iam untag-user --user-name dirk-bedrock --tag-keys manager-locked
   # Error: UnauthorizedOperation - UntagUser is denied for users in your namespace
   ```

**IAM Policy Statements**:

- ✅ `ManageRestrictionTags`: Allows `iam:TagUser` and `iam:ListUserTags` on namespace users
- ❌ `PreventTagRemovalOrModification`: Denies `iam:UntagUser` on namespace users

**Use Case**:

- Manager sets up restriction tags when creating user
- Manager can view tags to audit what restrictions are in place
- Tags remain permanent (manager cannot remove them)
- Provides tamper-proof audit trail
- Prevents accidental or malicious tag removal

## Configuration

### SSH Key Requirements

**Current System**:
```
Key Type:     ED25519 (256-bit) ✓ EXCELLENT
Protection:   AES-256-CTR ✓ EXCELLENT
Permissions:  600 ✓ CORRECT
```

**If Your Key is Unprotected**:
```bash
ssh-keygen -p -f ~/.ssh/id_ed25519
# Enter old passphrase: [press Enter if none]
# Enter new passphrase: [type strong passphrase]
# Confirm new passphrase: [re-type]
```

### Using ssh-agent for Passphrase Caching

```bash
# Start ssh-agent
eval $(ssh-agent -s)

# Add your key (you'll be prompted once for passphrase)
ssh-add ~/.ssh/id_ed25519

# Now encryption/decryption won't prompt for passphrase
iam-sorry --profile usermanager --encrypt
eval $(iam-sorry --eval usermanager)

# Kill agent when done
ssh-agent -k
```

### Custom SSH Key Path

To use a different SSH key, modify the script:

```python
# In iam-sorry tool, change:
def get_ssh_key_path():
    return os.path.expanduser("~/.ssh/id_ed25519")

# To:
def get_ssh_key_path():
    return os.path.expanduser("~/.ssh/my-custom-key")
```

## Troubleshooting

### "SSH key is not password protected"

```
Error: SSH key '/home/user/.ssh/id_ed25519' is not password protected.
For security, only password-protected SSH keys can be used for encryption.
Add a passphrase: ssh-keygen -p -f /home/user/.ssh/id_ed25519
```

**Solution**:
```bash
ssh-keygen -p -f ~/.ssh/id_ed25519
# Add a strong passphrase
```

### "Cannot encrypt 'default' profile"

```
Error: Cannot encrypt 'default' profile. Use --profile or AWS_PROFILE
to specify an explicit profile name.
```

**Solution**: Always use an explicit profile name:
```bash
iam-sorry --profile usermanager --encrypt
```

### "Could not determine IAM user"

```
Error: Could not determine IAM user for profile 'admin'
```

**Solution**: Create the profile first:
```bash
iam-sorry --profile usermanager admin
```

### "Profile does not exist"

```
Error: Manager profile 'usermanager' not found in credentials file
```

**Solution**: Add the profile to `~/.aws/credentials`:
```ini
[usermanager]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
```

### SSH Agent Not Available

```
⚠ ssh-agent not available or not running
```

**Solution**: Start ssh-agent:
```bash
eval $(ssh-agent -s)
ssh-add ~/.ssh/id_ed25519
```

## Examples

### Example 1: Setup & Encrypt

```bash
# 1. Install
pip install boto3 botocore cryptography

# 2. Add manager profile to ~/.aws/credentials
cat >> ~/.aws/credentials << 'EOF'
[usermanager]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF

# 3. Encrypt
iam-sorry --profile usermanager --encrypt

# 4. Verify
iam-sorry --show-encrypted usermanager
```

### Example 2: Batch IAM Provisioning

```bash
#!/bin/bash
# provision-users.sh

eval $(iam-sorry --eval usermanager)

for username in alice bob charlie; do
  echo "Creating user: $username"
  aws iam create-user --user-name $username

  echo "Creating access key for: $username"
  KEY=$(aws iam create-access-key --user-name $username \
    --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)

  echo "AccessKeyId: $(echo $KEY | cut -f1)"
  echo "SecretAccessKey: $(echo $KEY | cut -f2)"
done

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

### Example 3: Batch CloudFormation

```bash
#!/bin/bash
# deploy-stacks.sh

eval $(iam-sorry --eval usermanager)

REGIONS=("us-east-1" "us-west-2" "eu-west-1")
STACK_NAME="my-infrastructure"

for region in "${REGIONS[@]}"; do
  echo "Deploying to: $region"
  aws cloudformation create-stack \
    --region $region \
    --stack-name $STACK_NAME \
    --template-body file://template.yaml \
    --capabilities CAPABILITY_IAM
done

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

## Performance

- **Credential Generation**: ~2-5 seconds (depends on IAM lookup)
- **Encryption**: <100ms per credential
- **Decryption**: <100ms per credential
- **Batch Operations**: No overhead beyond normal AWS CLI/SDK

## Compatibility

- **Python**: 3.6+
- **OS**: Linux, macOS, WSL2
- **AWS SDK**: Works with any tool using `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`

## Security Considerations

### Best Practices

1. **Keep SSH Key Secure**
   - Never share your SSH key
   - Use strong passphrase (20+ characters)
   - Store on secure hardware if possible

2. **Use SSH-Agent**
   - Cache SSH passphrase with ssh-agent
   - Avoid typing passphrase repeatedly
   - Clear agent after batch operations

3. **Temporary Credentials Only**
   - Rotate temporary credentials regularly
   - Use maximum practical duration
   - Let credentials auto-expire

4. **Batch Operations**
   - Run in isolated bash sessions
   - Always unset environment variables after
   - Avoid storing credentials in scripts

5. **Monitoring**
   - Enable CloudTrail for audit
   - Monitor credential usage
   - Alert on unusual activity

### What This Tool DOES Protect

- ✅ Manager credentials encrypted at-rest
- ✅ Encryption key never stored (derived from SSH key)
- ✅ Passphrase-protected SSH key required
- ✅ Random nonces per encryption
- ✅ Auto-expiring temporary credentials

### What This Tool DOESN'T Protect

- ❌ Shell history (credentials visible in `~/.bash_history`)
- ❌ Process listing (credentials visible in `ps` during execution)
- ❌ SSH key compromise (if attacker gets SSH key, they get credentials)
- ❌ Unencrypted profiles (bedrock, admin remain plaintext)

## Contributing

Report issues or suggest improvements by opening a GitHub issue.

## License

Specify your license here (MIT, Apache 2.0, etc.)

## Author

Created with focus on practical AWS credential security for DevOps and infrastructure automation workflows.

## Related Tools

- **aws-vault**: Alternative credential encryption tool (uses OS keyring)
- **aws-cli**: Official AWS command-line interface
- **aws-iam**: AWS IAM management tool
- **aws-sso**: AWS Identity Center for organizations
- **kinit / kerberos**: For future Kerberos-based authentication integration
- **sssd**: System Security Services Daemon for AD/Kerberos integration

## FAQ

### Q: Why ED25519 instead of RSA?
**A**: ED25519 is modern, provides 256-bit security, and has better performance than RSA 4096-bit.

### Q: Can I use multiple SSH keys?
**A**: Currently the tool uses `~/.ssh/id_ed25519`. You can modify the script to support custom paths.

### Q: What if I forget my SSH passphrase?
**A**: You'll need to reset it with `ssh-keygen -p`. You may need to re-encrypt credentials with the new passphrase.

### Q: Can I use this with AWS SSO?
**A**: No, this tool requires IAM user credentials. For organizations, AWS SSO is recommended instead.

### Q: What happens if AWS STS is down?
**A**: Credential generation will fail. You can use cached temporary credentials or permanent credentials.

### Q: Can I automate without passphrase prompts?
**A**: Yes, use `ssh-agent` to cache the passphrase. See "Using ssh-agent" section.

### Q: Is this production-ready?
**A**: Yes, but test thoroughly in your environment. The encryption is solid, but credential management should always be tested carefully.
