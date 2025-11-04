# AWShawk
A precision AWS credential hunter designed for penetration testing. AWShawk performs non-root reconnaissance on Linux bastion hosts, EC2 instances, and compromised systems to discover exposed AWS credentials, secrets, and misconfigurations.


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.linux.org/)
[![Bash](https://img.shields.io/badge/Bash-5.0+-green.svg)](https://www.gnu.org/software/bash/)

---

## 🎯 Features

- **Non-Root Operation**: Runs with standard user privileges
- **Modular Scanning**: Enable only the checks you need with granular flags
- **Wide Mode**: Comprehensive filesystem crawl from `/` (excludes noisy system dirs)
- **Severity Scoring**: Automatic risk classification (Critical/High/Medium/Low)
- **Unified Reporting**: CSV index, scored findings, and Markdown reports
- **Secret Detection**: Pattern matching for AKIA/ASIA keys, secret keys, session tokens
- **Git History Scanning**: Integrated gitleaks & trufflehog support
- **IMDS Enumeration**: EC2 instance metadata service (IMDSv2 + IMDSv1 fallback)
- **STS Validation**: Optional identity verification for discovered credentials
- **Redacted Summaries**: Safe-to-share reports with masked secrets

---

## 🚀 Quick Start
```bash
# Clone the repository
git clone https://github.com/G0ldSec/AWShawk.git
cd AWShawk

# Make executable
chmod +x awshawk.sh

# (Optional) Install the helpers for the best results
chmod +x install_helpers.sh
./install_helpers.sh

# Run all checks with wide mode and redacted summary
./awshawk.sh -all -wide -redact

# Results saved to: ./results/<timestamp>-aws-bastion/
```

---

## 📋 Usage
```bash
./awshawk.sh [flags]
```

### Core Flags

| Flag | Description |
|------|-------------|
| `-all` | Run all checks (env, awsdir, patterns, suspicious, repos, imds) |
| `-env` | Capture AWS-related environment variables |
| `-awsdir` | Snapshot `~/.aws` directory (credentials, config, SSO cache) |
| `-patterns` | Deep content scan for AWS access keys and secrets |
| `-suspicious` | Detect suspicious filenames using heuristics |
| `-repos` | Run gitleaks/trufflehog on discovered Git repositories |
| `-imds` | Query EC2 Instance Metadata Service for role credentials |
| `-sts` | Validate discovered credentials via read-only STS calls |
| `-redact` | Generate additional redacted summary (safe for sharing) |

### Path Control

| Flag | Description |
|------|-------------|
| `-wide` | Crawl all readable paths from `/` (comprehensive scan) |
| `-nowide` | Force narrow mode (home dirs + common paths only) |
| `-paths "a:b:c"` | Add extra search roots (colon-separated) |

### Help

| Flag | Description |
|------|-------------|
| `-h` / `-help` | Show usage information |

---

## ⚙️ Configuration

Control scan behavior via environment variables:
```bash
# Enable wide mode
export SCAN_WIDE=true

# Increase search depth (default: 8)
export MAX_DEPTH=12

# Increase max file size to scan (default: 5MB)
export MAX_SIZE_BYTES=$((10*1024*1024))

# Aggressively scan binary files (default: false)
export SCAN_BINARIES=true

./awshawk.sh -all
```

---

## 📊 Output Structure
```
results/<timestamp>-aws-bastion/
├── FINDINGS.md              # Markdown report with severity-sorted findings
├── hits_index.csv           # Raw CSV index of all discoveries
├── hits_scored.csv          # Scored findings with severity levels
├── summary.txt              # Human-readable summary
├── summary.redacted.txt     # Redacted summary (if -redact used)
├── run.log                  # Execution log
├── basic_info.txt           # System information
├── paths_considered.txt     # Search paths used
├── env_aws_vars.txt         # AWS environment variables
├── aws_home/                # ~/.aws snapshot
│   ├── credentials
│   ├── config
│   └── cli_cache/
├── suspicious_filenames.txt
├── aws_pattern_hits.txt     # Content matches with line numbers
├── imds.txt                 # IMDS metadata
├── imds_creds.json          # Instance role credentials
├── gitleaks-*.json          # Gitleaks scan results
├── trufflehog-*.json        # Trufflehog scan results
└── sts_*.json               # STS validation results
```

---

## 🎨 Examples

### Basic Scan (Home Directory)
```bash
./awshawk.sh -env -awsdir -patterns
```

### Full Reconnaissance with Wide Mode
```bash
./awshawk.sh -all -wide -redact
```

### Deep Scan with Custom Settings
```bash
MAX_DEPTH=15 MAX_SIZE_BYTES=$((20*1024*1024)) \
  ./awshawk.sh -all -wide -paths "/data:/backup"
```

### IMDS + Credential Validation
```bash
./awshawk.sh -imds -sts -env -awsdir
```

---

## 🔍 Detection Patterns

AWShawk hunts for:

### AWS Credentials
- Access Key IDs: `AKIA[0-9A-Z]{16}`
- Session Keys: `ASIA[0-9A-Z]{16}`
- Temporary Tokens: `A3T[A-Z0-9]{13}`
- Secret Access Keys (via keyword patterns)
- Session Tokens

### Configuration Files
- `~/.aws/credentials`, `~/.aws/config`
- Environment variables (`AWS_*`, `ACCESS_KEY`, `SECRET_KEY`)
- `.env`, `.env.*` files
- Serverless configs (`serverless.yml`)
- Application properties files

### Suspicious Patterns
- Files named `credentials`, `secrets`, `config`
- AWS-related filenames in web roots (`/var/www`, `/srv`)
- Git repositories with leaked secrets (via gitleaks/trufflehog)

---

## 🛡️ Severity Scoring

| Severity | Criteria |
|----------|----------|
| **Critical** | Access Key ID + Secret Key found in same file |
| **High** | Secret keys, AKIA/ASIA keys in sensitive locations (.env, .tfstate, web roots) |
| **Medium** | Isolated access keys, session tokens, SSO configs |
| **Low** | Benign config (regions, profile names) |

**Special Cases:**
- IMDSv1 accessible without token → **High**

---

## 🔒 OPSEC Considerations

### For Red Teams
- ✅ Non-root execution leaves minimal footprint
- ✅ No package installations required
- ✅ Bundled tools run from `./helper/` (no system modifications)
- ⚠️ `-wide` mode touches many files (may trigger file integrity monitors)
- ⚠️ `-sts` flag makes network calls to AWS API (logs on CloudTrail)
- ⚠️ IMDS queries may be logged by instance monitoring

### For Blue Teams
- All findings include file paths and line numbers for remediation
- Use `FINDINGS.md` for prioritized response
- Review `summary.redacted.txt` for safe documentation
- Check `run.log` for scan coverage and errors

---

## 📦 Helper Binaries

Place these in `./helper/` for full functionality:

| Binary | Purpose | Required For |
|--------|---------|--------------|
| `gitleaks` | Git secret scanning | `-repos` |
| `trufflehog` | Filesystem secret scanning | `-repos` |
| `aws` | AWS CLI for STS validation | `-sts` |
| `jq` | JSON parsing |

*All binaries optional; AWShawk adapts to available tools.*

---

## 🧪 Testing

Test AWShawk in a controlled environment:
```bash
# Create test scenario
mkdir -p /tmp/test-target
echo 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' > /tmp/test-target/.env
echo 'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' >> /tmp/test-target/.env

# Run scan
./awshawk.sh -patterns -suspicious -paths "/tmp/test-target"

# Check results
cat results/*/FINDINGS.md
```

---

## 🤝 Contributing

Contributions welcome! Areas for enhancement:

- Additional cloud provider support (Azure, GCP)
- Custom regex pattern support
- Enhanced redaction rules
- Performance optimizations for massive filesystems
- CI/CD integration examples

---

## ⚠️ Legal Disclaimer

**AWShawk is designed for authorized security testing only.**

- ✅ Use only on systems you own or have explicit written permission to test
- ✅ Respect all applicable laws and regulations
- ✅ Follow responsible disclosure practices
- ❌ Unauthorized access to computer systems is illegal

The author is not responsible for misuse or damage caused by this tool.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details

---

## 🙏 Acknowledgments

- [Gitleaks](https://github.com/gitleaks/gitleaks) - Git secret scanning
- [Trufflehog](https://github.com/trufflesecurity/trufflehog) - Credential discovery
- AWS documentation and security best practices

---

## 📬 Contact

For bugs, feature requests, or security concerns, please open an issue on GitHub.

---
## 💌 Coming Soon:
- **Terraform Analysis**: Deep inspection of `.tfstate`, `.tfvars` files
