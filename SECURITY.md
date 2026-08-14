# Security Policy

PLAIK treats security, data integrity and safe extension boundaries as release requirements.

## Reporting a vulnerability

Please do **not** open a public issue for a vulnerability that could expose secrets, authentication bypasses, authorization failures, remote code execution, package-signature bypasses, path traversal, SQL injection, XSS/CSRF, SSRF or unsafe deployment behavior.

Until a dedicated security contact is published, use GitHub's private vulnerability reporting for this repository when available.

Include:

- affected version or commit;
- reproduction steps;
- expected and observed behavior;
- impact and required preconditions;
- suggested mitigation if known.

Do not include real production credentials, private keys, customer data or production `.env` contents in reports.

## Scope

The public PLAIK repositories contain product code and generic reference configuration only. Host-specific infrastructure, production credentials and private operational evidence are intentionally kept outside the public repositories.
