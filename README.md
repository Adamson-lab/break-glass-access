# 🔴 Break-Glass: Emergency Access with Tamper-Evident Audit Trail

**The problem:** at 3 a.m. production is down, SSO is broken or the only person with root is asleep. Someone must get privileged access *now*, yet regulators (SOX, PCI DSS, FFIEC, FedRAMP, HIPAA) require that every emergency grant is justified, approved by a second person, time-limited, fully logged and reviewed afterwards. Most firms do this with a shared password in a safe and a spreadsheet. This repo is a working implementation.

```bash
# Windows without make: python scripts/demo.py | python app/breakglass.py | python -m unittest -v tests/test_breakglass.py
make demo     # watch a full P1 incident + an attack on the audit log, in your terminal
make run      # live console at http://localhost:8080  (or: make up for Docker)
make test     # 5 tests proving the controls
```
Zero dependencies. Python 3.9+ standard library only.

## Architecture
```mermaid
flowchart LR
  subgraph People
    R["Requester - on-call SRE"]
    A["Approver - second person"]
    U["Auditor - independent"]
  end

  subgraph BG["Break-Glass Service"]
    API["REST API + RBAC"]
    SW["Expiry sweeper"]
    AUD[("Hash-chained append-only audit")]
    DB[("Requests")]
  end

  V["Vault / PAM / Jump host"]
  SIEM["SIEM / Pager"]
  WORM[("WORM anchor - S3 Object Lock")]

  R -->|"1 request + ticket"| API
  A -->|"2 approve"| API
  R -->|"3 checkout once"| API
  R -->|"4 use token"| V
  V -->|"validate"| API
  U -->|"5 mandatory review"| API
  API --> DB
  API --> AUD
  SW --> DB
  SW --> AUD
  AUD -->|"every event"| SIEM
  AUD -.->|"hourly head hash"| WORM

  classDef person fill:#fdd,stroke:#c0392b,color:#000
  classDef external fill:#dde,stroke:#334aa0,color:#000
  class R,A,U person
  class V,SIEM,WORM external
```

## Incident lifecycle
```mermaid
sequenceDiagram
  autonumber
  participant R as Requester
  participant S as Service
  participant A as Approver
  participant V as Vault
  participant U as Auditor
  R->>S: POST /requests (resource, INC ticket, reason, ≤60 min)
  S-->>A: SIEM alert + page
  R->>S: approve (self)
  S-->>R: 403 + SELF_APPROVAL_BLOCKED logged
  A->>S: POST approve
  Note over S: clock starts, expires = now + minutes
  R->>S: POST checkout
  S-->>R: one-time token (only hash stored)
  R->>V: use token
  V->>S: validate
  S-->>V: granted + audit USE
  alt incident resolved early
    A->>S: revoke
  else time runs out
    S->>S: auto EXPIRE
  end
  S-->>U: review queue
  U->>S: verdict justified / unjustified + note
```

## State machine
```mermaid
stateDiagram-v2
  [*] --> PENDING
  PENDING --> APPROVED: approver ≠ requester
  PENDING --> DENIED: approver + note
  APPROVED --> EXPIRED: timer
  APPROVED --> REVOKED: approver / auditor
  EXPIRED --> REVIEWED: auditor verdict
  REVOKED --> REVIEWED: auditor verdict
  DENIED --> [*]
  REVIEWED --> [*]
```

## Tamper-evident audit log
Each row's hash covers the previous hash, so editing any row breaks every row after it. SQL triggers block `UPDATE`/`DELETE`; the chain catches anyone who bypasses the triggers (`make demo` shows exactly that).
```mermaid
flowchart LR
  G["genesis 000...0"] --> E1["1 REQUEST - h1 = SHA256 of genesis + event1"]
  E1 --> E2["2 APPROVE - h2 = SHA256 of h1 + event2"]
  E2 --> E3["3 USE - h3 = SHA256 of h2 + event3"]
  E3 --> E4["4 REVOKE - h4 = SHA256 of h3 + event4"]
  E3 -.->|"attacker edits actor"| X["h3 no longer matches - verify reports broken_at 3"]

  classDef bad fill:#fdd,stroke:#c0392b,color:#000
  class X bad
```

## Threat model
| Threat | Mitigation |
|---|---|
| Insider approves own request | Dual-control check, attempt itself is logged |
| Token stolen/replayed | One-time checkout, hash-only storage, expiry, revoke |
| Standing access creeping in | Hard 60-min cap, auto-expiry |
| Admin edits log to hide misuse | Triggers + hash chain; production: external anchor (see docs/CONTROLS.md) |
| Nobody reviews afterwards | Every revoke/expiry opens a review item |
| Fake "emergencies" | Ticket pattern + reason required, every request alerts |

## API
`POST /requests` · `GET /requests` · `POST /requests/{id}/approve|deny|checkout|revoke|review` · `POST /vault/use` (header `X-Break-Glass-Token`) · `GET /audit` · `GET /audit/verify` · `GET /reviews/pending`
Demo personas (Bearer tokens): `t-alice` requester, `t-bob`/`t-carol` approvers, `t-dave` auditor.

See [docs/CONTROLS.md](docs/CONTROLS.md) for the compliance mapping and production hardening checklist.
