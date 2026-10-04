# MalSense Lab — Client-Side Email Security & Threat Inspector

> **MalSense Lab** is an offline, client-side email security inspector and heuristic triage engine. It analyzes raw email text and RFC headers to detect domain spoofing, deceptive links, credential harvesting, and punitive social engineering patterns in real time.

100% private — all parsing and heuristic rules execute locally in client memory. **Zero network transmission.**

---

## Key Features

- **Domain Alignment Check (`SenderLinkDomainMismatch`)**:
  - Extracts root domains (eTLD+1) from `From:` headers (including bare domains, angle brackets, and email addresses) and from all extracted destination URLs.
  - Automatically identifies domain mismatches between sender and destination targets (+25 pts).
- **Sensitive URL Path & Query Inspection (`SensitiveActionUrl`)**:
  - Parses URLs and inspects pathname and query parameters for sensitive actions (`/login`, `/signin`, `/auth`, `/verify`, `/portal`, `/update`, `/reset`).
  - Flags external unauthorized domains attempting credential harvests (+18 pts).
- **Protocol Security Verification (`InsecureProtocolLink`)**:
  - Detects unencrypted `http://` links (+10 pts) and specifically warns when accompanied by sensitive authentication paths.
- **Punitive Coercion Detection (`CoerciveConsequence`)**:
  - Flags punitive threats beyond basic urgency, including network restriction, account termination, disciplinary action, and access revocation (+15 pts).
- **Header & Identity Integrity**:
  - Analyzes `From` vs. `Reply-To` routing mismatches, plus SPF, DKIM, and DMARC alignment markers.
- **Comprehensive Threat Assessment Export**:
  - Generates clear, plain-text incident reports with verdict badges, numeric scores (0–100), itemized indicators of compromise, extracted destination metadata, and tailored remediation advice.

---

## Quick Start

### 1. Web Interface
Simply open `index.html` in any modern web browser:
```bash
# Double click or open in browser
index.html
```
No build steps, no external runtime dependencies, and no backend server required.

### 2. Run Tests
The test suite runs on Node.js using the native test runner:
```bash
npm test
```

---

## Threat Scoring & Risk Tiers

| Score Range | Verdict | Action Required |
|---|---|---|
| **0 – 29** | `CLEAN / LOW RISK` | Standard operational awareness |
| **30 – 59** | `POTENTIAL RISK` | Moderate threat signals; verify out-of-band |
| **60 – 100** | `CRITICAL THREAT` | High probability of malicious intent; isolate and report |

---

## File Structure

```
malsense-lab/
├── analyser.js           # Core heuristic engine, header parser, and link triage
├── demo-emails.js        # Built-in realistic test cases (including HR spear-phishing)
├── index.html            # Dark-mode cybersecurity workbench interface
├── styles.css            # Responsive, high-contrast UI design system
├── package.json          # Project metadata and test runner scripts
├── test/
│   └── analyser.test.js  # Automated unit tests covering all detection heuristics
└── README.md             # Project documentation
```

---

## Author

Developed by **[Vaishak](https://github.com/vaishak-io)**
