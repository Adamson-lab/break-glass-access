# Control mapping (what an auditor will ask for)

| Requirement | Where it is enforced | Test |
|---|---|---|
| Two-person integrity / separation of duties (SOX 404, NIST 800-53 AC-5, ISO 27001 A.5.3) | `action()`: requester cannot approve; auditor cannot request or approve | `test_dual_control` |
| Least privilege, time-limited access (AC-6, AC-2(2) emergency/temporary accounts) | `MAX_MIN` cap, auto-expiry sweeper | `test_validation`, `test_auto_expiry_forces_review` |
| Emergency access procedure (NIST AC-14, HIPAA 164.312(a)(2)(ii), FFIEC) | Ticket-bound request, reason min length | `test_validation` |
| Non-repudiation / audit protection (AU-9, AU-10, AU-10(1)) | SHA-256 hash chain + SQL triggers block UPDATE/DELETE | `test_tamper_detected...` |
| Credential hygiene | One-time checkout, only SHA-256 stored, revocation | `test_full_lifecycle_and_audit` |
| Post-event review (AU-6, CA-7) | Every EXPIRE/REVOKE creates a mandatory auditor review | `test_auto_expiry_forces_review` |

## Production hardening checklist (not in the demo)
1. Replace static `BG_USERS` tokens with OIDC (Entra ID/Okta) + phishing-resistant MFA on approve.
2. Ship `siem` stdout lines to Splunk/Sentinel; alert on every `REQUEST` (page the CISO on-call) and every `SELF_APPROVAL_BLOCKED`.
3. Anchor `head` hash externally every hour (WORM bucket / S3 Object Lock / transparency log). A DBA with full DB rights can rewrite the *whole* chain; external anchoring defeats that.
4. Swap SQLite for Postgres with a role that has INSERT-only on `audit`.
5. Replace `/vault/use` with a real integration: HashiCorp Vault dynamic creds, CyberArk, AWS IAM Identity Center, Azure PIM.
6. Run 2+ replicas behind a load balancer; test the break-glass path itself quarterly (the control must work when SSO is down).
