# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| `main` branch | ✅ Active |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, **please do not open a public GitHub issue**.

Report it privately via **GitHub Security Advisories**:

1. Go to the [Security tab](https://github.com/goku-70/iac-compliance-audit/security/advisories/new)
2. Click **"New draft security advisory"**
3. Describe the vulnerability, steps to reproduce, and potential impact

You can also email **gokutestdev@gmail.com** with the subject line `[SECURITY] iac-compliance-audit`.

I aim to acknowledge reports within **48 hours** and provide a fix or mitigation plan within **7 days** for CRITICAL and HIGH severity issues.

## Security Design Notes

This tool is designed to audit other people's infrastructure code. The following design decisions are intentional:

- **No file writes outside the report directory.** The skill instructs Claude never to write files to disk; `scan.sh` handles all persistence via shell redirection.
- **No network calls beyond the Anthropic API.** The skill only reads local files and calls cloud CLIs the user has already authenticated.
- **Path traversal protection.** `scan.sh` validates `--path` against `..` before and after `realpath` resolution.
- **Input validation.** All CLI flags are validated against an allowlist before being passed to Claude.
- **API key hygiene.** The key is read from the environment and never logged, echoed, or written to disk. In CI mode, `scan.sh` avoids printing any environment variable values.
- **Least-privilege GitHub Actions permissions.** The bundled workflow requests only `contents: read`, `pull-requests: write`, and `actions: read`.
- **Pinned third-party actions.** All `uses:` references in `action.yml` are pinned to full SHA to prevent supply-chain attacks via tag mutation.
- **Self-contained HTML reports.** No CDN dependencies — reports contain zero third-party requests and are safe for air-gapped or restricted environments.
