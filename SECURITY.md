# Security Policy

## ⚠️ Security Notice

> [!WARNING]
> **This project has not yet undergone an independent security or cryptographic audit.**
>
> The hybrid post-quantum cryptographic primitives and protocols implemented in this repository are intended for **research, development, and evaluation purposes only**. While we strive to follow cryptographic best practices, the implementation has **not** been formally audited by an independent security firm.
>
> **Do not use this software in production environments or to secure high-value assets** until a comprehensive security audit has been completed and the findings have been addressed.

## Supported Versions

At this time, only the latest commit on the default branch is actively maintained. Security fixes will not be backported to older releases unless explicitly stated.

| Version                 | Supported |
| ----------------------- | --------- |
| Latest (default branch) | ✅         |

## Reporting a Vulnerability

We take security seriously and appreciate responsible disclosure from the security research community.

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, report vulnerabilities privately by emailing:

**📧 [no-reply@tyconnzsolutions.com](mailto:no-reply@tyconnzsolutions.com)**

Please include as much information as possible, including:

* A clear description of the vulnerability.
* Affected components or modules.
* Steps to reproduce the issue.
* A proof of concept (PoC), if available.
* Potential impact and attack scenario.
* Any suggested mitigation or remediation.

## Response Process

After receiving your report, we will:

1. Acknowledge receipt within **48 hours**.
2. Investigate and validate the reported issue.
3. Work with the reporter under a **coordinated vulnerability disclosure** process.
4. Develop and test a fix where appropriate.
5. Publicly disclose the vulnerability after a patch is available, unless a different timeline is mutually agreed upon.

## Scope

This policy applies to all source code and components contained within this repository, including but not limited to:

* Hybrid post-quantum cryptographic implementations
* Consensus and networking components
* Wallet and key management code
* Serialization and protocol logic
* Build and deployment scripts

## Security Best Practices

If you are evaluating or testing this project:

* Use only on isolated development or testing environments.
* Never use real private keys or production assets.
* Assume that undiscovered vulnerabilities may exist.
* Keep dependencies up to date and verify their integrity.
* Review all cryptographic parameters before deployment.

## Disclosure Policy

We ask that security researchers avoid publicly disclosing vulnerabilities until we have had a reasonable opportunity to investigate and release a fix.

We greatly appreciate responsible disclosure and collaboration in improving the security of this project.

---

Thank you for helping improve the security and reliability of this project.
