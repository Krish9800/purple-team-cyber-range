# Purple-Team Cyber Range: STRIDE Threat Model

**Document ID**: `PURPLE-RANGE-SEC-001`  
**Classification**: Engineering Security Architecture  
**Standards**: Microsoft STRIDE, MITRE ATT&CK Enterprise v14, NIST SP 800-115  
**Review Status**: APPROVED  

---

## 1. System Overview & Trust Boundaries

The **Purple-Team Cyber Range** executes adversary emulation sequences (Red Team) and automatically validates ingested sensor alerts (Blue Team) to calculate Detection Coverage Rates (DCR) and synthesize Sigma rules.

```
       [ External Sensor / SIEM / EDR ]
                      │  (Ingest Alerts)
                      ▼
[ Operator / CLI ] ──► [ Trust Boundary: REST API / CLI ]
                               │
               ┌───────────────┴───────────────┐
               ▼                               ▼
       [ Emulation Engine ]           [ Evaluator & DB ]
               │ (Sandboxed Exec)              │
               ▼                               ▼
    [ Cyber Range Target Host ]        [ SQLite WAL Data ]
```

### Trust Zones
1. **Zone 0 (Unprivileged External Sensors)**: External telemetry sources streaming security alerts. Untrusted inputs must be validated and normalized.
2. **Zone 1 (Purple Range Control Plane)**: FastAPI application, Typer CLI, and Orchestrator service running under non-root system account (UID `10001`).
3. **Zone 2 (Target Execution Boundary)**: Safe execution environment where atomic technique commands run with strict preflight validation and non-destructive parameters.
4. **Zone 3 (Data Persistence Layer)**: Local SQLite WAL database storing campaigns, execution journals, and Sigma recommendations.

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Threat Scenario | Impact | Architectural Mitigation | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing (S)** | An attacker injects falsified alerts claiming a technique was detected when no alert occurred. | False sense of security; inflated DCR metric. | Temporal correlation window ($\Delta t \le 120$s), process PID validation, and host attribution matching. | Mitigated |
| **Tampering (T)** | Attacker tampers with command parameters to execute destructive payloads (e.g., `rm -rf /` or fork bombs). | Host compromise or data loss outside range boundary. | `PreFlightValidator` regex blocklist; parameterized command templates; non-root user execution. | Mitigated |
| **Repudiation (R)** | Operator denies initiating an offensive emulation sequence on a target host. | Audit failure, non-traceable cyber range actions. | Immutable SQLite execution journal logging operator ID, exact UTC timestamps, PID, and command hashes. | Mitigated |
| **Information Disclosure (I)** | Unauthorized party queries gap analysis reports to discover defensive blind spots. | Attacker exploits known undetected MITRE techniques. | Localhost API binding; role isolation; database file access controls (`chmod 600`). | Mitigated |
| **Denial of Service (D)** | Adversary technique loops infinitely, exhausting CPU or thread pools. | Cyber range server becomes unresponsive. | Mandatory subprocess timeout enforcement (`wait_for` with default 30s timeout); process kill on timeout. | Mitigated |
| **Elevation of Privilege (E)** | Attacker breaks out of emulation container to gain root access on the host node. | Complete host compromise. | Rootless Docker image (UID/GID `10001`); `cap_drop: ALL`; `no-new-privileges: true`. | Mitigated |

---

## 3. Security Quality Gate & Continuous Assurance

- **Static Analysis (SAST)**: Bandit scan with zero medium/high vulnerabilities.
- **Strict Typing**: Mypy `--strict` disallowing untyped functions or any implicit optionals.
- **Test Enforcement**: Pytest with 90%+ branch and line coverage requirement.
- **Safe Rollback**: Mandatory idempotent cleanup handlers revert target system changes.
