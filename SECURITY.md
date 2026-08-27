# Security Policy

NEMOS is a defensive monitoring project. Please do not disclose live credentials, private packet captures, or sensitive infrastructure details in public issues.

## Reporting a vulnerability
For a vulnerability in NEMOS itself, use a private security report through the repository hosting platform if available. Include:
- affected version/commit
- reproducible steps
- impact
- relevant logs or minimal proof of concept

Do not include secrets or unrelated personal data.

## Deployment guidance
- Keep the dashboard on loopback unless remote access is deliberately configured.
- If remote access is enabled, set `NEMOS_API_TOKEN` and use HTTPS/reverse-proxy controls.
- For wildcard binds (`0.0.0.0`, `::`, `*`), also set `NEMOS_TRUSTED_HOSTS` to the exact hostnames/IPs clients should use; the application refuses an unbounded wildcard Host policy.
- Run packet capture with the minimum Linux capabilities required.
- Keep Python and dependencies patched.
- Treat alerts as detection signals, not proof of compromise.
