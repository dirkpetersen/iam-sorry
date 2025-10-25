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

### Prerequisites

```bash
# Python 3.6+
python3 --version

# AWS credentials for a manager IAM user (temporary profile)
# A password-protected ED25519 SSH key (~/.ssh/id_ed25519)

# Install dependencies
pip install boto3 botocore cryptography
```

### Basic Usage

```bash
# 1. Store your manager profile (one-time)
# Edit ~/.aws/credentials with your manager IAM credentials:
[usermanager]
aws_access_key_id = AKIA...
aws_secret_access_key = ...

# 2. Encrypt the manager profile (one-time)
iam-sorry --profile usermanager --encrypt
# ✓ Manager profile 'usermanager' encrypted with SSH key

# 3. Generate temporary credentials
iam-sorry --profile usermanager admin
# ✓ Successfully updated profile 'admin'
# ✓ Credentials expire at: 2025-10-26T12:00:00

# 4. Run batch operations
eval $(iam-sorry --eval usermanager)

for user in user1 user2 user3; do
  aws iam create-user --user-name $user
done

# 5. Cleanup
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

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
│  ├─ SAML / OAuth                                          │
│  └─ Browser-based SSO                                     │
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
- Browser-based authentication (AD/SAML)
- No credentials stored on individual machines

### Current vs. Future Tradeoffs

| Aspect | Current (SSH-Key) | Future (Service) |
|--------|-------------------|------------------|
| **Setup** | Per-user (self-service) | Per-department (IT-managed) |
| **Auth** | SSH passphrase | Active Directory / SSO |
| **Credentials** | Distributed (each user) | Centralized (service only) |
| **Audit Trail** | Limited (per-machine logs) | Complete (all via service) |
| **Offline Access** | ✓ Yes | ✗ No (requires network) |
| **Headless Systems** | ✓ Excellent | ✗ Needs browser |
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

### 3. Setup Manager Profile

Add your IAM manager credentials to `~/.aws/credentials`:

```ini
[usermanager]
aws_access_key_id = AKIA...
aws_secret_access_key = ...
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
