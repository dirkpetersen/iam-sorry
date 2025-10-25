# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**aws-creds** is a Python CLI utility that manages temporary AWS credentials for IAM users with optional SSH-key based encryption. It integrates with AWS IAM and STS to fetch short-lived session tokens, encrypt them optionally, and update local AWS credential profiles with full security controls.

**Key Innovation**: Powerful manager profile credentials can be encrypted at-rest using your ED25519 SSH key, then decrypted on-demand for batch operations—no plaintext on disk.

## Architecture

**Single-file design**: The entire application is in `aws-creds` (Python 3 script, ~700 lines).

### Core Workflow

1. **Credential Generation**:
   - Takes a manager profile (from `--profile` or `AWS_PROFILE` env var)
   - Takes a target profile/username to manage
   - Looks up IAM user (via existing access key or username)
   - Calls AWS STS `GetSessionToken` for temporary credentials
   - Updates target profile with credentials

2. **Encryption** (optional):
   - Validates SSH key is ED25519 and password-protected
   - Derives AES-256 key from SSH key using HKDF
   - Encrypts access key and secret key individually with AES-256-GCM
   - Stores with `__encrypted__:` prefix
   - Session token remains unencrypted (temporary)

3. **Decryption & Injection** (for batch mode):
   - Auto-detects encrypted credentials
   - Decrypts on-demand using SSH key
   - Outputs shell export statements
   - User runs `eval` to inject into environment

### Profile Types & Security Model

```
Manager Profile (usermanager)
├─ Type: Permanent credentials (high privilege)
├─ Encryption: ✓ Optional (must be explicitly named)
├─ Risk: HIGH (data access)
├─ Usage: Only for generating other credentials
└─ Storage: Encrypted in ~/.aws/credentials

Service Profile (bedrock)
├─ Type: Permanent credentials (low privilege)
├─ Encryption: ✗ Not encrypted (permanent but low risk)
├─ Risk: LOW (financial only)
├─ Usage: Direct service access
└─ Storage: Plaintext in ~/.aws/credentials

Generated Profile (admin, dev, etc)
├─ Type: Temporary credentials
├─ Encryption: ✗ Not encrypted (by design)
├─ Risk: LOW (time-limited)
├─ Usage: Batch operations, limited scope
└─ Storage: Plaintext in ~/.aws/credentials
```

### Main Functions

**Encryption/Decryption**:
- `is_ssh_key_password_protected()` - Validates SSH key protection (OPENSSH format parsing)
- `encrypt_credential()` - Encrypts individual credentials with AES-256-GCM
- `decrypt_credential()` - Decrypts individual credentials
- `decrypt_profile_credentials()` - Auto-decrypts all encrypted fields in a profile
- `derive_encryption_key_from_ssh_key()` - Derives AES-256 key from SSH key via HKDF

**Credential Management**:
- `get_iam_user_for_access_key()` - Iterates all IAM users to find access key owner
- `verify_iam_user_exists()` - Checks if IAM username exists
- `get_temp_credentials_for_user()` - Calls STS GetSessionToken (max 36 hours)
- `update_profile_credentials()` - Writes to `~/.aws/credentials` with 0600 permissions
- `read_aws_credentials()` - Reads credentials with optional auto-decryption
- `write_aws_credentials()` - Writes credentials with proper permissions

**Username Prefix Validation**:
- `extract_username_prefix()` - Extracts prefix from username (everything before first hyphen)
- `validate_username_prefix()` - Validates that target username matches manager's prefix
- `generate_usermanager_policy()` - Generates IAM policy with prefix-based resource restrictions

**CLI**:
- `main()` - Orchestrates workflow with argument parsing

### Username Prefix-Based Access Control

The tool enforces username prefix matching to prevent unauthorized user management. This provides namespace isolation between different managers.

**How It Works**:

1. **Prefix Extraction**: Extract everything before the first hyphen
   - `dirk-admin` → prefix is `dirk`
   - `alice-manager` → prefix is `alice`
   - `bob` → prefix is `bob`

2. **Validation Rules**:
   - Manager can create/manage users starting with `{prefix}-`
   - Manager can create/manage user with exact prefix name (but not themselves)
   - All other usernames are rejected

3. **Enforcement Layers**:
   - **CLI Validation**: Client-side check before AWS API calls (immediate feedback)
   - **IAM Policy**: Server-side enforcement at AWS level (security boundary)

**Examples**:

```python
# Manager: dirk-admin (prefix: dirk)
validate_username_prefix("dirk-admin", "dirk-bedrock")  # ✓ Valid
validate_username_prefix("dirk-admin", "dirk")          # ✓ Valid
validate_username_prefix("dirk-admin", "alice")         # ✗ Invalid

# Manager: dirk (prefix: dirk)
validate_username_prefix("dirk", "dirk-bedrock")        # ✓ Valid
validate_username_prefix("dirk", "dirk")                # ✗ Invalid (self)
```

**IAM Policy Generation**:

The `generate_usermanager_policy()` function automatically creates resource restrictions:

```json
{
  "Resource": [
    "arn:aws:iam::123456789012:user/dirk",
    "arn:aws:iam::123456789012:user/dirk-*"
  ]
}
```

This ensures AWS enforces the prefix restriction even if the CLI validation is bypassed.

### Tagging Strategy for Permanent Restrictions

The IAM policy includes statements to enforce permanent restrictions via tagging:

**AddRestrictionTags Statement**:
- Allows `iam:TagUser` on prefix-matched users
- Managers can apply restriction tags during user setup
- Tags are one-time setup operations

**PreventTagRemoval Statement**:
- Denies `iam:UntagUser` on prefix-matched users
- Uses Effect: Deny (explicit deny overrides any allow)
- Prevents managers from removing tags after initial setup
- Ensures restrictions remain permanent and tamper-proof

**Use Cases**:
- Manager applies tags to newly created users
- Tags define access controls, service restrictions, cost centers, etc.
- Once applied, tags cannot be modified by the same manager
- Provides audit trail and prevents privilege escalation

**Example Policy Section**:
```json
{
  "Sid": "AddRestrictionTags",
  "Effect": "Allow",
  "Action": ["iam:TagUser"],
  "Resource": ["arn:aws:iam::123456789012:user/dirk", "arn:aws:iam::123456789012:user/dirk-*"]
},
{
  "Sid": "PreventTagRemoval",
  "Effect": "Deny",
  "Action": ["iam:UntagUser"],
  "Resource": ["arn:aws:iam::123456789012:user/dirk", "arn:aws:iam::123456789012:user/dirk-*"]
}
```

## Command Reference

### Basic Credential Generation

```bash
# Generate temporary credentials using environment variable
AWS_PROFILE=usermanager ./aws-creds admin

# Using command-line argument
./aws-creds --profile usermanager admin

# Specify duration (1-36 hours, default: 36)
./aws-creds --profile usermanager --duration 12 admin

# Refresh default profile (prompts for confirmation)
AWS_PROFILE=usermanager ./aws-creds
```

### Encryption (Manager Profile Only)

```bash
# One-time: Encrypt the manager profile
./aws-creds --profile usermanager --encrypt

# View encrypted credentials (ciphertext)
./aws-creds --show-encrypted usermanager

# View decrypted credentials (plaintext, requires SSH passphrase)
./aws-creds --show-decrypted usermanager
```

### Batch Operations (Environment Injection)

```bash
# Generate temporary credentials for batch operations
./aws-creds --profile usermanager admin

# Inject into environment (auto-decrypts if encrypted)
eval $(./aws-creds --eval admin)

# Run batch IAM operations
for user in user1 user2 user3; do
  aws iam create-user --user-name $user
  aws iam attach-user-policy --user-name $user --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
done

# Cleanup
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

## SSH Key-Based Encryption

### Requirements

- **Key Type**: ED25519 (256-bit) or equivalent strength
  - Current key: ✓ ED25519 256-bit (EXCELLENT)
  - Alternative: RSA 4096-bit (GOOD)
  - Not recommended: RSA 2048-bit (WEAK)

- **Key Protection**: Must be password-protected
  - Script validates automatically before encryption
  - Uses OPENSSH format cipher field detection
  - Rejects unprotected keys with clear error message

- **Key Location**: `~/.ssh/id_ed25519` (configurable in code)

### How Encryption Works

1. **Key Validation**:
   ```
   OPENSSH format → Extract cipher field
   cipher = "none" → NOT encrypted → REJECT
   cipher = "aes256-ctr" → ENCRYPTED → ACCEPT
   ```

2. **Key Derivation**:
   ```
   SSH Private Key
   ↓ (HKDF-SHA256)
   AES-256 Encryption Key (32 bytes)
   ```

3. **Credential Encryption**:
   ```
   Credential Value
   ↓ (AES-256-GCM with random nonce)
   Ciphertext + Nonce
   ↓ (Base64 encode)
   __encrypted__:<base64>
   ```

4. **Storage**:
   ```ini
   [usermanager]
   aws_access_key_id = __encrypted__:pdZLbbMlei28ZA0vhsT6gesOG6BLB...
   aws_secret_access_key = __encrypted__:1vYfR8x2kjhsRR0vhsT6gesOG6B...
   aws_session_token = ASIAQXXXXXXX...
   credentials_owner = usermanager
   ```

5. **Decryption**:
   ```
   On-demand when needed
   ↓ (Read encrypted value)
   ↓ (Derive key from SSH key)
   ↓ (AES-256-GCM decrypt with stored nonce)
   Plaintext credential
   ↓ (In memory only, never on disk)
   Injected into environment via eval
   ```

### Usage Examples

```bash
# ✓ CORRECT: Encrypt manager profile with explicit name
./aws-creds --profile usermanager --encrypt

# ✗ ERROR: Cannot encrypt default profile
AWS_PROFILE=default ./aws-creds --encrypt
# Error: Cannot encrypt 'default' profile. Use --profile or AWS_PROFILE to specify an explicit profile name.

# ✗ ERROR: Unprotected SSH key
# Error: SSH key '/home/user/.ssh/id_ed25519' is not password protected.
# For security, only password-protected SSH keys can be used for encryption.
# Add a passphrase: ssh-keygen -p -f /home/user/.ssh/id_ed25519

# Generate other profiles (never encrypted, by design)
./aws-creds --profile usermanager admin
./aws-creds --profile usermanager bedrock

# View storage
./aws-creds --show-encrypted usermanager   # Encrypted
./aws-creds --show-decrypted usermanager   # Decrypted (requires passphrase)
./aws-creds --show-decrypted admin         # Plaintext (no passphrase)
```

### Security Guarantees

- ✓ **Only password-protected keys allowed** - Validated automatically
- ✓ **Encryption key never on disk** - Derived on-demand from SSH key
- ✓ **Random nonce per encryption** - Different ciphertext each time
- ✓ **Credentials in memory only** - Not persisted after eval
- ✓ **SSH passphrase required** - Unless cached via ssh-agent
- ✓ **Temporary credentials short-lived** - Max 36 hours, auto-expire

### Adding Passphrase to SSH Key

```bash
# If your SSH key is unprotected
ssh-keygen -p -f ~/.ssh/id_ed25519

# You'll be prompted:
# Enter old passphrase: [leave blank if not protected]
# Enter new passphrase: [enter strong passphrase]
# Confirm new passphrase: [re-enter]
```

## Environment Variable Injection (--eval)

### Primary Use Case

Batch operations requiring powerful manager profile credentials without storing them in plaintext.

```bash
# Encrypt manager profile (one-time)
./aws-creds --profile usermanager --encrypt

# Later: Inject encrypted credentials for batch operation
eval $(./aws-creds --eval usermanager)

# Batch provisioning with high-privilege access
for region in us-east-1 us-west-2 eu-west-1; do
  aws cloudformation create-stack \
    --region $region \
    --stack-name my-stack \
    --template-body file://template.yaml
done

# Cleanup
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

### How It Works

```bash
# For encrypted profiles
./aws-creds --eval usermanager
  1. Read encrypted credentials from ~/.aws/credentials
  2. Validate SSH key is password protected
  3. Decrypt using SSH key (prompts for passphrase if needed)
  4. Output export statements with decrypted values

# For plaintext profiles
./aws-creds --eval bedrock
  1. Read plaintext credentials from ~/.aws/credentials
  2. Output export statements directly
```

### Output

```bash
export AWS_ACCESS_KEY_ID='AKIAIOSFODNN7EXAMPLE'
export AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
export AWS_SESSION_TOKEN='ASIAQXXXXXXX...'
```

### Security Considerations

- Credentials visible in shell history (`~/.bash_history`)
- Credentials visible in `ps` output during execution
- Only suitable for temporary or low-risk credentials
- For encrypted manager profile: High-privilege access is protected by SSH passphrase
- Always unset environment variables after use
- Best practice: Use in isolated bash sessions or scripts, not interactive shells

## Implementation Details

### Dependencies

```
boto3            # AWS SDK (AWS credential generation)
botocore         # Low-level AWS communication
cryptography     # Encryption (AES-256-GCM, HKDF)
```

Install: `pip install boto3 botocore cryptography`

### Key Design Decisions

1. **GetSessionToken for Temporary Credentials**:
   - Max 36 hours (STS limit)
   - Doesn't require MFA for basic usage
   - Suitable for most automation workflows

2. **Metadata Storage**:
   - Stores `credentials_owner` to identify IAM user
   - Persists across credential rotation
   - Allows recovery of user info after temp credentials expire

3. **Encryption Scope**:
   - Only encrypts `aws_access_key_id` and `aws_secret_access_key`
   - `aws_session_token` remains unencrypted (temporary)
   - `credentials_owner` remains plaintext (metadata)

4. **Error Handling**:
   - Distinguishes `NoSuchEntity` (not found) from other AWS errors
   - Always sets 0600 permissions on credentials file
   - Clear error messages with actionable fixes

5. **Performance**:
   - Lazy decryption: Only decrypt when needed
   - IAM lookup: Can be slow in accounts with many users (paginated)
   - SSH key parsing: Fast OPENSSH format parsing

### Code Structure

```
aws-creds (Python 3 script)
├── Imports & constants
├── Encryption functions
│   ├── is_ssh_key_password_protected()
│   ├── derive_encryption_key_from_ssh_key()
│   ├── encrypt_credential()
│   ├── decrypt_credential()
│   └── decrypt_profile_credentials()
├── Credential functions
│   ├── get_iam_user_for_access_key()
│   ├── verify_iam_user_exists()
│   ├── get_temp_credentials_for_user()
│   └── update_profile_credentials()
├── File I/O functions
│   ├── get_aws_credentials_path()
│   ├── read_aws_credentials()
│   └── write_aws_credentials()
└── main()
    ├── Argument parsing
    ├── Flag handlers (--encrypt, --show-encrypted, --show-decrypted, --eval)
    └── Workflow orchestration
```

## Development Notes

### Testing Encryption

```python
# Manual test
python3 << 'EOF'
exec(open('aws-creds').read().split('def main():')[0])

ssh_key_path = get_ssh_key_path()
is_protected = is_ssh_key_password_protected(ssh_key_path)
print(f"Key protected: {is_protected}")

test_cred = "AKIAIOSFODNN7EXAMPLE"
encrypted = encrypt_credential(test_cred, ssh_key_path)
decrypted = decrypt_credential(encrypted, ssh_key_path)
assert test_cred == decrypted
print("✓ Encryption roundtrip successful")
EOF
```

### Adding New Encryption Methods

To add alternative encryption (GPG, master password, etc):

1. Add validation function: `is_key_suitable_for_encryption(key_path)`
2. Add encryption function: `encrypt_credential_with_method(value, key_path)`
3. Add decryption function: `decrypt_credential_with_method(value, key_path)`
4. Update `encrypt_credential()` to support method selection
5. Update `decrypt_profile_credentials()` to auto-detect method

### Performance Considerations

- **IAM Lookup**: O(n*m) where n=users, m=keys per user
  - Mitigated by pagination
  - Consider caching for large accounts (1000+ users)

- **Decryption**: O(1) per credential
  - Only happens when needed
  - SSH passphrase entry is the bottleneck (human input)

- **Credential File I/O**: O(1)
  - File is typically small (<10KB)

## Related AWS Best Practices

1. **Use IAM Roles**: Prefer roles over long-lived credentials
2. **AWS SSO**: For organizations, use AWS IAM Identity Center
3. **Temporary Credentials**: Prefer short-lived tokens (aws-creds does this)
4. **MFA**: Enable for IAM users with powerful permissions
5. **CloudTrail**: Audit credential usage
6. **Secrets Manager**: For application secrets, not user credentials
