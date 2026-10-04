const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
  analyseEmail,
  extractRootDomain,
  extractSenderRootDomain,
  getSensitiveActionMatch,
  isInsecureHttp,
  detectSenderLinkDomainMismatch,
  detectSensitiveActionUrl,
  detectInsecureProtocolLink,
  generateReportText,
  buildRecommendations,
  classify,
} = require("../analyser.js");

describe("Phishing Email Analyser - Detection Engine", () => {
  describe("1. Root Domain (eTLD+1) Extraction", () => {
    it("extracts root domain from standard URLs", () => {
      assert.strictEqual(
        extractRootDomain("http://phishing-simulation-target.example.net/hr/login"),
        "example.net"
      );
      assert.strictEqual(
        extractRootDomain("https://portal.internal-corp-portal.com/dashboard"),
        "internal-corp-portal.com"
      );
    });

    it("extracts root domain from multi-part ccTLDs (.co.uk, .com.au, .gov.uk)", () => {
      assert.strictEqual(
        extractRootDomain("https://secure.login.service.gov.uk/auth"),
        "service.gov.uk"
      );
      assert.strictEqual(
        extractRootDomain("https://mail.corp.co.uk/owa"),
        "corp.co.uk"
      );
      assert.strictEqual(
        extractRootDomain("https://banking.westpac.com.au/login"),
        "westpac.com.au"
      );
    });

    it("extracts root domain from email addresses and From headers", () => {
      assert.strictEqual(
        extractRootDomain("compliance@internal-corp-portal.com"),
        "internal-corp-portal.com"
      );
      assert.strictEqual(
        extractSenderRootDomain(null, "HR Operations <compliance@internal-corp-portal.com>"),
        "internal-corp-portal.com"
      );
      assert.strictEqual(
        extractSenderRootDomain(null, "internal-corp-portal.com"),
        "internal-corp-portal.com"
      );
      assert.strictEqual(
        extractSenderRootDomain(null, "<internal-corp-portal.com>"),
        "internal-corp-portal.com"
      );
    });

    it("handles IP addresses and localhost", () => {
      assert.strictEqual(extractRootDomain("http://192.168.1.50:8080/login"), "192.168.1.50");
      assert.strictEqual(extractRootDomain("http://localhost:3000"), "localhost");
    });
  });

  describe("2. Domain Alignment Check (SenderLinkDomainMismatch)", () => {
    it("flags sender vs link root domain mismatch with High severity (+25 pts)", () => {
      const email = `From: HR Portal <compliance@internal-corp-portal.com>
Subject: Policy Review

Please review here: http://phishing-simulation-target.example.net/hr/login`;

      const result = analyseEmail(email);
      const mismatchFinding = result.findings.find(
        (f) => f.id === "SenderLinkDomainMismatch"
      );

      assert.ok(mismatchFinding, "Expected SenderLinkDomainMismatch to trigger");
      assert.strictEqual(mismatchFinding.severity, "High");
      assert.strictEqual(mismatchFinding.points, 25);
      assert.ok(mismatchFinding.evidence.includes("internal-corp-portal.com"));
      assert.ok(mismatchFinding.evidence.includes("example.net"));
      assert.strictEqual(mismatchFinding.metadata.senderDomain, "internal-corp-portal.com");
      assert.strictEqual(mismatchFinding.metadata.targetDomain, "example.net");
    });

    it("does not trigger when link domain aligns with sender root domain", () => {
      const email = `From: HR Portal <compliance@internal-corp-portal.com>
Subject: Policy Review

Please review here: https://sso.internal-corp-portal.com/hr/login`;

      const result = analyseEmail(email);
      const mismatchFinding = result.findings.find(
        (f) => f.id === "SenderLinkDomainMismatch"
      );

      assert.strictEqual(mismatchFinding, undefined, "Aligned domain must not trigger mismatch");
    });
  });

  describe("3. Sensitive URL Path & Keyword Detection (SensitiveActionUrl)", () => {
    const sensitiveActions = [
      "/login",
      "/signin",
      "/auth",
      "/verify",
      "/portal",
      "/update",
      "/reset",
    ];

    sensitiveActions.forEach((action) => {
      it(`detects sensitive path "${action}" on external domain (+18 pts)`, () => {
        const email = `From: Security <alerts@company.com>
Subject: Action Needed

Link: https://external-attacker.org/service${action}`;

        const result = analyseEmail(email);
        const finding = result.findings.find((f) => f.id === "SensitiveActionUrl");
        assert.ok(finding, `Expected SensitiveActionUrl for path ${action}`);
        assert.strictEqual(finding.severity, "High");
        assert.strictEqual(finding.points, 18);
        assert.strictEqual(finding.metadata.sensitiveAction, action);
      });
    });

    it("detects sensitive actions inside query parameters", () => {
      const email1 = `From: Helpdesk <it@company.com>
Subject: Auth Required
Link: https://external-host.net/app?action=login`;

      const res1 = analyseEmail(email1);
      assert.ok(res1.findings.some((f) => f.id === "SensitiveActionUrl"));

      const email2 = `From: Helpdesk <it@company.com>
Subject: Verify Required
Link: https://external-host.net/gateway?redirect=/verify&token=abc`;

      const res2 = analyseEmail(email2);
      assert.ok(res2.findings.some((f) => f.id === "SensitiveActionUrl"));
    });

    it("does NOT trigger when sensitive action URL is on the internal sender domain", () => {
      const email = `From: Helpdesk <it@company.com>
Subject: Official Sign-in
Link: https://auth.company.com/login`;

      const result = analyseEmail(email);
      const finding = result.findings.find((f) => f.id === "SensitiveActionUrl");
      assert.strictEqual(finding, undefined, "Internal domain sensitive actions should not trigger external flag");
    });
  });

  describe("4. Insecure Protocol Flag (InsecureProtocolLink)", () => {
    it("flags unencrypted http:// links (+10 pts)", () => {
      const email = `Check our docs: http://public-docs.example.org/guide`;
      const result = analyseEmail(email);
      const finding = result.findings.find((f) => f.id === "InsecureProtocolLink");
      assert.ok(finding, "InsecureProtocolLink should trigger for http://");
      assert.strictEqual(finding.severity, "Medium");
      assert.strictEqual(finding.points, 10);
    });

    it("specifically notes when http:// link is accompanied by a login/auth path", () => {
      const email = `Login here: http://phishing-simulation-target.example.net/hr/login`;
      const result = analyseEmail(email);
      const finding = result.findings.find((f) => f.id === "InsecureProtocolLink");
      assert.ok(finding);
      assert.ok(finding.evidence.includes('sensitive action path ("/login")'));
    });

    it("does not flag encrypted https:// links", () => {
      const email = `Secure: https://encrypted-portal.example.com/`;
      const result = analyseEmail(email);
      const finding = result.findings.find((f) => f.id === "InsecureProtocolLink");
      assert.strictEqual(finding, undefined);
    });
  });

  describe("5. Coercive Consequence Heuristic (CoerciveConsequence)", () => {
    const coercivePhrases = [
      "restrict network access",
      "account termination",
      "will be suspended",
      "disciplinary action",
      "access will be revoked",
      "penalty",
      "immediate termination",
    ];

    coercivePhrases.forEach((phrase) => {
      it(`triggers on coercive consequence phrase "${phrase}" (+15 pts)`, () => {
        const email = `Notice: Compliance failure will lead to ${phrase} without delay.`;
        const result = analyseEmail(email);
        const finding = result.findings.find((f) => f.id === "CoerciveConsequence");
        assert.ok(finding, `Expected CoerciveConsequence to match "${phrase}"`);
        assert.strictEqual(finding.severity, "Medium");
        assert.strictEqual(finding.points, 15);
      });
    });

    it("avoids false positives on negations like 'without penalty' or 'no disciplinary action'", () => {
      const email = `You may complete this survey without penalty. No disciplinary action is planned.`;
      const result = analyseEmail(email);
      const finding = result.findings.find((f) => f.id === "CoerciveConsequence");
      assert.strictEqual(finding, undefined, "Negated phrases must not trigger coercion rule");
    });
  });

  describe("6. HR Spear-Phishing Test Scenario (Full Stacking & Threat Report)", () => {
    const hrEmail = `From: internal-corp-portal.com
Subject: Employee Policy Compliance

Please acknowledge the revised policy immediately.
Failure to complete this acknowledgment will restrict network access.

Link: http://phishing-simulation-target.example.net/hr/login`;

    it("accurately detects all 4 new indicators and scores >= 60 (Critical Threat)", () => {
      const result = analyseEmail(hrEmail);

      // Verify triggered rule IDs
      const triggeredIds = result.findings.map((f) => f.id);
      assert.ok(triggeredIds.includes("SenderLinkDomainMismatch"), "Missing SenderLinkDomainMismatch");
      assert.ok(triggeredIds.includes("SensitiveActionUrl"), "Missing SensitiveActionUrl");
      assert.ok(triggeredIds.includes("InsecureProtocolLink"), "Missing InsecureProtocolLink");
      assert.ok(triggeredIds.includes("CoerciveConsequence"), "Missing CoerciveConsequence");

      // Verify points:
      // SenderLinkDomainMismatch (25) + SensitiveActionUrl (18) + CoerciveConsequence (15) + InsecureProtocolLink (10) + Urgency (12) = 80
      assert.ok(result.score >= 60, `Score was ${result.score}, expected >= 60`);
      assert.strictEqual(result.classification.key, "high");
      assert.strictEqual(result.classification.level, "High Risk");
      assert.strictEqual(result.classification.badge, "CRITICAL THREAT");
    });

    it("reaches >= 60 points even without keyword urgency", () => {
      const hrEmailWithoutUrgency = `From: internal-corp-portal.com
Subject: Employee Policy Compliance

Please acknowledge the revised policy.
Failure to complete this acknowledgment will restrict network access.

Link: http://phishing-simulation-target.example.net/hr/login`;

      const result = analyseEmail(hrEmailWithoutUrgency);
      // 25 + 18 + 15 + 10 = 68 points
      assert.strictEqual(result.score, 68);
      assert.ok(result.score >= 60);
      assert.strictEqual(result.classification.badge, "CRITICAL THREAT");
    });

    it("generates comprehensive threat report with metadata and remediation", () => {
      const result = analyseEmail(hrEmail);
      const report = generateReportText(result);

      assert.ok(report.includes("EMAIL THREAT ASSESSMENT REPORT"));
      assert.ok(report.includes("CRITICAL THREAT (High Risk)"));
      assert.ok(report.includes("internal-corp-portal.com"));
      assert.ok(report.includes("example.net"));
      assert.ok(report.includes("Sender-to-Link Domain Mismatch (+25 pts)"));
      assert.ok(report.includes("Sensitive Action Path on External Domain (+18 pts)"));
      assert.ok(report.includes("Punitive Coercion & Access Threat (+15 pts)"));
      assert.ok(report.includes("Insecure Protocol Link (HTTP) (+10 pts)"));
      assert.ok(report.includes("DOMAIN MISMATCH"));
      assert.ok(report.includes("SENSITIVE ACTION"));
      assert.ok(report.includes("INSECURE HTTP"));
      assert.ok(report.includes("[Domain Spoof]"));
      assert.ok(report.includes("[Credential Safety]"));
      assert.ok(report.includes("[Insecure Link]"));
      assert.ok(report.includes("[Policy / Coercion]"));
    });

    it("properly calibrates clean legitimate emails", () => {
      const cleanEmail = `From: Alex Rivera <alex.rivera@northwind-example.com>
To: team@northwind-example.com
Subject: Team Sync Notes

Hi team, here are the meeting notes for our upcoming project milestones.
Please review the doc: https://docs.northwind-example.com/notes

Best regards,
Alex`;

      const result = analyseEmail(cleanEmail);
      assert.ok(result.score < 30, `Clean email score was ${result.score}, expected < 30`);
      assert.strictEqual(result.classification.key, "low");
      assert.strictEqual(result.classification.level, "Low Risk");
      assert.strictEqual(result.classification.badge, "CLEAN / LOW RISK");
    });
  });
});
