# Security Policy

NEMOS is a defensive monitoring project. Please do not disclose live
credentials, private packet captures, or sensitive infrastructure details in
public issues.

## Supported versions

| Version | Supported |
| --- | --- |
| 4.1.x | Yes |
| < 4.1 | No — please upgrade |

Fixes are applied to the latest release. There is no long-term support branch.

## Reporting a vulnerability

For a vulnerability in NEMOS itself, use GitHub's private vulnerability
reporting on this repository ("Security" → "Report a vulnerability") rather than
a public issue. Include:

- affected version or commit
- reproducible steps
- impact
- relevant logs or a minimal proof of concept

Do not include secrets, third-party data, or unrelated personal information.

Expect an initial acknowledgement within a week. This is a small project without
a dedicated security team, so please size your expectations accordingly — but a
credible report will be taken seriously and credited unless you prefer
otherwise.

## Scope

**In scope:** authentication bypass on the API, injection, unbounded resource
consumption from crafted traffic, credential disclosure through logs or
endpoints, and privilege issues in the packaged systemd unit.

**Out of scope:** missing detections and false negatives. NEMOS is a monitoring
tool with deliberately conservative thresholds; an attack it fails to detect is
a detection-quality issue, not a vulnerability. Please open a normal issue with
the traffic pattern instead — those reports are genuinely useful.

## Deployment guidance

- Keep the dashboard on loopback unless remote access is deliberately
  configured.
- If remote access is enabled, set `NEMOS_API_TOKEN` and put HTTPS and a reverse
  proxy in front of it.
- For wildcard binds (`0.0.0.0`, `::`, `*`), also set `NEMOS_TRUSTED_HOSTS` to
  the exact hostnames or IPs clients will use. NEMOS refuses to start with an
  unbounded wildcard Host policy.
- Run packet capture with the minimum Linux capability required (`CAP_NET_RAW`).
  Do not run the web application as root.
- Keep `.env` out of version control and readable only by the service account.
- **Treat the trained model as trusted input.** Loading it deserialises a
  scikit-learn object, which can execute code if the file is attacker-controlled.
  NEMOS writes it 0600 inside a 0700 directory and never fetches a model over the
  network or accepts one through the API. Do not point `NEMOS_MODEL_DIR` at a
  location other users can write to, and do not install a model from an
  untrusted source.
- The optional LLM analyst is off unless `NEMOS_LLM_PROVIDER` is set. When
  enabled with a hosted provider, evidence bundles describing your network are
  sent to that provider. Use the `ollama` provider to keep everything local.
  NEMOS refuses to redirect a hosted provider's endpoint, so a misconfigured
  variable cannot retarget that data.
- Keep Python and dependencies patched; `pip-audit` runs in CI but only against
  pinned versions at the time of the run.
- Treat alerts as detection signals, not proof of compromise.

## Authorized use

Only monitor networks you own or are explicitly authorized to monitor.
Intercepting traffic without authorization is illegal in most jurisdictions.
