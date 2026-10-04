/**
 * Phishing Email Analyzer — Heuristic Rule & Inspection Engine
 * Executes 100% client-side in the browser. Zero network transmission.
 */

(function () {
  "use strict";

  const RULES = [
    {
      id: "urgency",
      category: "Social Engineering",
      title: "Manufactured Urgency",
      severity: "Medium",
      points: 12,
      explanation: "Applies artificial time pressure ('immediately', '24 hours', 'action required') to rush the recipient into acting before thinking.",
      patterns: [
        /\b(urgent(?:ly)?|immediately|right\s+away|act\s+now|within\s+\d+\s+hours?|expires?\s+(today|soon)|final\s+notice|limited\s+time|asap|do\s+not\s+delay|respond\s+now)\b/i,
      ],
    },
    {
      id: "suspension",
      category: "Social Engineering",
      title: "Account Lockout or Closure Threat",
      severity: "High",
      points: 18,
      explanation: "Threatens immediate account closure, deactivation, or lockout to trigger anxiety.",
      patterns: [
        /\b(account\s+(will\s+be\s+)?(locked|closed|deactivated)|close\s+your\s+account|account\s+lockout)\b/i,
      ],
    },
    {
      id: "CoerciveConsequence",
      category: "Social Engineering",
      title: "Punitive Coercion & Access Threat",
      severity: "Medium",
      points: 15,
      explanation: "Threatens punitive repercussions, access restrictions, or disciplinary actions to coerce immediate compliance through fear.",
      patterns: [
        /\b(restrict(?:ed|ing)?\s+(?:your\s+)?network\s+access|account\s+termination|will\s+be\s+suspended|disciplinary\s+actions?|access\s+(?:will\s+be\s+)?revoked|penalt(?:y|ies)|immediate\s+termination)\b/i,
      ],
    },
    {
      id: "password_request",
      category: "Credentials & Fraud",
      title: "Direct Password Request",
      severity: "Critical",
      points: 25,
      explanation: "Legitimate services never ask you to submit your password or credentials via email or unverified forms.",
      patterns: [
        /\b(confirm|verify|send|provide|enter|update|share)\b.{0,40}\b(password|passwd|passcode)\b/i,
        /\b(password|passwd)\b.{0,40}\b(confirm|verify|send|provide|enter|update|share)\b/i,
        /\b(current\s+password|your\s+password\s+is\s+required)\b/i,
      ],
    },
    {
      id: "mfa_request",
      category: "Credentials & Fraud",
      title: "MFA / OTP Code Solicitation",
      severity: "Critical",
      points: 22,
      explanation: "Attempts to intercept 2FA codes, security tokens, or one-time passcodes to hijack active sessions.",
      patterns: [
        /\b(mfa|2fa|two[-\s]?factor|one[-\s]?time\s+(pass)?code|otp|verification\s+code|security\s+code|authentication\s+code)\b/i,
        /\b(send|reply\s+with|provide|share)\b.{0,30}\b(code|token)\b/i,
      ],
    },
    {
      id: "payment_giftcard",
      category: "Credentials & Fraud",
      title: "Unusual Payment or Gift Card Demand",
      severity: "Critical",
      points: 24,
      explanation: "Demands non-traceable, irreversible payment forms (gift cards, wire transfers, crypto wallets, or obscure fees).",
      patterns: [
        /\b(gift\s*cards?|itunes\s+card|google\s+play\s+card|steam\s+card|prepaid\s+card)\b/i,
        /\b(wire\s+transfer|western\s+union|buy\s+gift\s+cards?|send\s+(payment|money)|pay\s+(immediately|now|via|a\s+(small\s+)?(redelivery\s+)?fee))\b/i,
        /\b(bitcoin|cryptocurrency|crypto\s+wallet|redelivery\s+fee|delivery\s+fee\s+due)\b/i,
      ],
    },
    {
      id: "bank_details",
      category: "Credentials & Fraud",
      title: "Bank Account / Routing Diversion",
      severity: "Critical",
      points: 24,
      explanation: "Requests unexpected revisions to bank details or payment routing — a hallmark of Business Email Compromise (BEC).",
      patterns: [
        /\b(update|change|revise|new)\b.{0,40}\b(bank\s+(account|details)|routing\s+number|sort\s+code|iban|wire\s+instructions|payment\s+details)\b/i,
        /\b(bank\s+(account|details)|payment\s+details)\b.{0,40}\b(update|change|revise|new)\b/i,
        /\b(redirect\s+(payment|funds)|alternate\s+account)\b/i,
      ],
    },
    {
      id: "SenderLinkDomainMismatch",
      category: "Links & URLs",
      title: "Sender-to-Link Domain Mismatch",
      severity: "High",
      points: 25,
      explanation: "The destination link root domain does not align with the sender's From domain, indicating domain spoofing or deceptive redirection.",
      test: detectSenderLinkDomainMismatch,
    },
    {
      id: "SensitiveActionUrl",
      category: "Links & URLs",
      title: "Sensitive Action Path on External Domain",
      severity: "High",
      points: 18,
      explanation: "Destination URL directs to an authentication, login, or verification path on a domain that does not match the sender.",
      test: detectSensitiveActionUrl,
    },
    {
      id: "InsecureProtocolLink",
      category: "Links & URLs",
      title: "Insecure Protocol Link (HTTP)",
      severity: "Medium",
      points: 10,
      explanation: "URL uses unencrypted HTTP rather than HTTPS, exposing transmission to interception or indicating rogue phishing infrastructure.",
      test: detectInsecureProtocolLink,
    },
    {
      id: "shortened_url",
      category: "Links & URLs",
      title: "Shortened URL",
      severity: "Medium",
      points: 14,
      explanation: "Uses redirect services (bit.ly, tinyurl, cutt.ly) to mask the ultimate target domain.",
      patterns: [
        /\bhttps?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly|cutt\.ly|shorturl\.at)\/\S+/i,
      ],
    },
    {
      id: "ip_url",
      category: "Links & URLs",
      title: "Raw IP Address in URL",
      severity: "High",
      points: 18,
      explanation: "Links directly to a numerical IP address rather than a registered hostname, typical of rogue hosting servers.",
      patterns: [
        /\bhttps?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/\S*)?/i,
      ],
    },
    {
      id: "suspicious_url",
      category: "Links & URLs",
      title: "High-Risk Domain or Deceptive Keyword",
      severity: "High",
      points: 15,
      explanation: "Contains high-risk TLDs (.xyz, .top, .icu) or crafted keywords mimicking official portals.",
      patterns: [
        /\bhttps?:\/\/[^\s]*?(secure-?login|account-?verify|verify-?account|signin-?secure|login-?update)[^\s]*/i,
        /\bhttps?:\/\/[^\s]+\.(xyz|top|icu|click|country|gq|tk|ml|cf|zip|mov)(?:\/|\b)/i,
        /\bhttps?:\/\/[^\s]*?(microsoft|apple|google|paypal|amazon|office365|outlook)[^\s]*\.(?!com\b|net\b|org\b)[a-z]{2,}\b/i,
      ],
    },
    {
      id: "misleading_link",
      category: "Links & URLs",
      title: "Mismatched Hyperlink Destination",
      severity: "High",
      points: 16,
      explanation: "Anchor text displays a legitimate brand address, but the underlying hyperlink points elsewhere.",
      test: detectMisleadingLinks,
    },
    {
      id: "impersonation",
      category: "Social Engineering",
      title: "Brand Impersonation Language",
      severity: "Medium",
      points: 12,
      explanation: "Borrows recognizable corporate or IT department branding to manufacture credibility.",
      patterns: [
        /\b(microsoft\s*365|office\s*365|outlook\s+security|apple\s+id|paypal\s+security|amazon\s+account|it\s+helpdesk|security\s+team|account\s+review\s+team)\b/i,
        /\b(dear\s+valued\s+(customer|member)|this\s+is\s+an\s+automated\s+(security\s+)?message)\b/i,
      ],
    },
    {
      id: "executable_attachment",
      category: "Attachments",
      title: "Executable / Script File Reference",
      severity: "Critical",
      points: 22,
      explanation: "Mentions or attaches executable file types (.exe, .scr, .bat, .vbs, .ps1) commonly used to deliver malware.",
      patterns: [
        /\b[\w.-]+\.(exe|scr|bat|cmd|js|vbs|wsf|ps1|msi|dll|jar|pif)\b/i,
        /\b(attached|attachment|file)\b.{0,40}\.(exe|scr|bat|cmd|js|vbs|ps1|msi)\b/i,
      ],
    },
    {
      id: "unusual_attachment",
      category: "Attachments",
      title: "Double Extension or Disguised Archive",
      severity: "Medium",
      points: 10,
      explanation: "Employs double extensions (e.g., .pdf.exe) or generic archives (.zip, .iso) to bypass filters.",
      patterns: [
        /\b[\w.-]+\.(pdf|doc|docx|xls|xlsx|txt)\.(exe|scr|js|vbs|bat|cmd|zip|rar)\b/i,
        /\b(invoice|payment|shipping|resume|cv)[\w.-]*\.(zip|rar|iso|img|html|htm)\b/i,
      ],
    },
    {
      id: "macros",
      category: "Attachments",
      title: "Macro Execution Request",
      severity: "Critical",
      points: 20,
      explanation: "Instructs recipient to enable macros or allow active content, a known payload execution vector.",
      patterns: [
        /\b(enable\s+macros?|enable\s+content|allow\s+macros?|macros?\s+must\s+be\s+enabled)\b/i,
      ],
    },
    {
      id: "invoice_bec",
      category: "Social Engineering",
      title: "Executive BEC / Secret Payment Request",
      severity: "High",
      points: 16,
      explanation: "Claims overdue invoices or executive wire instructions accompanied by requests for secrecy.",
      patterns: [
        /\b(outstanding\s+invoice|unpaid\s+invoice|attached\s+invoice|process\s+(this\s+)?payment|payment\s+overdue)\b/i,
        /\b(ceo|cfo|finance\s+director|managing\s+director)\b.{0,60}\b(urgent|wire|transfer|payment)\b/i,
        /\b(handle\s+this\s+discreetly|keep\s+this\s+confidential|do\s+not\s+discuss\s+with)\b/i,
      ],
    },
    {
      id: "credential_harvest",
      category: "Credentials & Fraud",
      title: "Credential Harvesting Lure",
      severity: "High",
      points: 18,
      explanation: "Directs recipient to external sign-in pages under the pretense of 'verifying ownership' or 'restoring mailbox'.",
      patterns: [
        /\b(verify\s+your\s+(identity|account|login)|re[-\s]?authenticate|confirm\s+your\s+(identity|credentials)|unlock\s+your\s+account)\b/i,
        /\b(click\s+(here|below)\s+to\s+(verify|login|sign\s*in|secure|restore)|sign\s*in\s+to\s+avoid)\b/i,
        /\b(validate\s+your\s+(mailbox|account)|confirm\s+ownership)\b/i,
      ],
    },
    {
      id: "reply_to_mismatch",
      category: "Headers & Identity",
      title: "Reply-To Domain Mismatch",
      severity: "Critical",
      points: 20,
      explanation: "The Reply-To address directs responses to an entirely different domain than the sender's From address.",
      test: detectReplyToMismatch,
    },
    {
      id: "spf_fail",
      category: "Headers & Identity",
      title: "SPF Verification Failure",
      severity: "High",
      points: 15,
      explanation: "The sending server IP is not authorized by the domain's SPF record.",
      patterns: [
        /\bspf\s*[=:]\s*(fail|softfail)\b/i,
        /\bReceived-SPF:\s*(fail|softfail)\b/i,
      ],
    },
    {
      id: "dkim_fail",
      category: "Headers & Identity",
      title: "DKIM Signature Failure",
      severity: "High",
      points: 15,
      explanation: "Cryptographic signature validation failed; message may have been forged or modified in transit.",
      patterns: [
        /\bdkim\s*[=:]\s*fail\b/i,
      ],
    },
    {
      id: "dmarc_fail",
      category: "Headers & Identity",
      title: "DMARC Alignment Failure",
      severity: "Critical",
      points: 18,
      explanation: "Message failed domain alignment checks, indicating unauthorized sender spoofing.",
      patterns: [
        /\bdmarc\s*[=:]\s*fail\b/i,
      ],
    },
  ];

  function detectMisleadingLinks(text) {
    const htmlAnchors = [...text.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)<\/a>/gis)];
    for (const match of htmlAnchors) {
      const href = match[1].trim();
      const label = match[2].replace(/<[^>]+>/g, "").trim();
      const labelUrl = extractUrl(label);
      if (labelUrl && urlsLikelyDiffer(labelUrl, href)) {
        return {
          matched: true,
          evidence: `Anchor text displays "${truncate(label, 45)}" but link actually opens "${truncate(href, 55)}"`,
        };
      }
    }

    const markdownLinks = [...text.matchAll(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/gi)];
    for (const match of markdownLinks) {
      const label = match[1].trim();
      const href = match[2].trim();
      const labelUrl = extractUrl(label);
      if (labelUrl && urlsLikelyDiffer(labelUrl, href)) {
        return {
          matched: true,
          evidence: `Anchor text displays "${truncate(label, 45)}" but link actually opens "${truncate(href, 55)}"`,
        };
      }
    }

    return { matched: false };
  }

  function detectReplyToMismatch(text) {
    const from = extractHeaderEmail(text, "From");
    const replyTo = extractHeaderEmail(text, "Reply-To") || extractHeaderEmail(text, "Reply To");
    if (!from || !replyTo) return { matched: false };

    const fromDomain = domainOf(from);
    const replyDomain = domainOf(replyTo);
    if (fromDomain && replyDomain && fromDomain !== replyDomain) {
      return {
        matched: true,
        evidence: `From domain is "@${fromDomain}", but Reply-To redirects to "@${replyDomain}"`,
      };
    }
    return { matched: false };
  }

  function detectSenderLinkDomainMismatch(text, context) {
    const senderRoot = (context && context.senderRootDomain) || extractSenderRootDomain(text);
    if (!senderRoot) return { matched: false };

    const links = (context && context.links) || extractAllLinks(text, senderRoot);
    if (!links || links.length === 0) return { matched: false };

    const mismatches = links.filter((l) => {
      const linkRoot = l.rootDomain || extractRootDomain(l.url);
      return linkRoot && linkRoot !== senderRoot;
    });

    if (mismatches.length > 0) {
      const first = mismatches[0];
      const linkRoot = first.rootDomain || extractRootDomain(first.url);
      const remaining = mismatches.length - 1;
      const more = remaining > 0 ? ` (+${remaining} other destination${remaining > 1 ? "s" : ""})` : "";
      return {
        matched: true,
        evidence: `Sender domain: "${senderRoot}" vs. Target link domain: "${linkRoot}" (${truncate(first.url, 65)})${more}`,
        metadata: {
          senderDomain: senderRoot,
          targetDomain: linkRoot,
          mismatchedCount: mismatches.length,
          mismatchedLinks: mismatches.map((m) => m.url),
        },
      };
    }
    return { matched: false };
  }

  function detectSensitiveActionUrl(text, context) {
    const senderRoot = (context && context.senderRootDomain) || extractSenderRootDomain(text);
    const links = (context && context.links) || extractAllLinks(text, senderRoot);
    if (!links || links.length === 0) return { matched: false };

    for (const link of links) {
      const linkRoot = link.rootDomain || extractRootDomain(link.url);
      const isMismatch = !senderRoot || (linkRoot && linkRoot !== senderRoot);
      if (!isMismatch) continue;

      const sensitive = link.sensitiveAction || getSensitiveActionMatch(link.url);
      if (sensitive) {
        return {
          matched: true,
          evidence: `Sensitive action "${sensitive}" found on external domain "${linkRoot || "Unknown"}": ${truncate(link.url, 70)}`,
          metadata: {
            sensitiveAction: sensitive,
            linkUrl: link.url,
            linkRootDomain: linkRoot || "Unknown",
            senderRootDomain: senderRoot || null,
          },
        };
      }
    }
    return { matched: false };
  }

  function detectInsecureProtocolLink(text, context) {
    const links = (context && context.links) || extractAllLinks(text);
    if (!links || links.length === 0) return { matched: false };

    const insecureLinks = links.filter((l) => l.isInsecure || isInsecureHttp(l.url));
    if (insecureLinks.length === 0) return { matched: false };

    // Check if any insecure link is accompanied by a sensitive action path
    const sensitiveInsecure = insecureLinks.find((l) => l.hasSensitivePath || getSensitiveActionMatch(l.url));
    if (sensitiveInsecure) {
      const action = sensitiveInsecure.sensitiveAction || getSensitiveActionMatch(sensitiveInsecure.url);
      return {
        matched: true,
        evidence: `Unencrypted HTTP link accompanied by sensitive action path ("${action}"): ${truncate(sensitiveInsecure.url, 70)}`,
        metadata: {
          insecureUrl: sensitiveInsecure.url,
          sensitiveAction: action,
          protocol: "http",
        },
      };
    }

    const first = insecureLinks[0];
    const remaining = insecureLinks.length - 1;
    const more = remaining > 0 ? ` (+${remaining} more)` : "";
    return {
      matched: true,
      evidence: `Unencrypted HTTP link detected: ${truncate(first.url, 70)}${more}`,
      metadata: {
        insecureUrl: first.url,
        protocol: "http",
      },
    };
  }

  function extractHeaderEmail(text, headerName) {
    const escaped = headerName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp("^" + escaped + "\\s*:\\s*(.+)$", "im");
    const match = text.match(regex);
    if (!match) return null;
    const emailMatch = match[1].match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
    return emailMatch ? emailMatch[0].toLowerCase() : null;
  }

  function extractHeaderValue(text, headerName) {
    const escaped = headerName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp("^" + escaped + "\\s*:\\s*(.+)$", "im");
    const match = text.match(regex);
    return match ? match[1].trim() : null;
  }

  function domainOf(email) {
    if (!email) return null;
    const parts = email.split("@");
    return parts.length === 2 ? parts[1].toLowerCase() : null;
  }

  function extractSenderRootDomain(text, fromHeaderValue) {
    const fromVal = fromHeaderValue || extractHeaderValue(text, "From");
    if (!fromVal) return null;

    // 1. Check for email address
    const emailMatch = fromVal.match(/[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})/i);
    if (emailMatch) {
      return extractRootDomain(emailMatch[1]);
    }

    // 2. Check for angle brackets <domain.com>
    const angleMatch = fromVal.match(/<([A-Z0-9.-]+\.[A-Z]{2,})>/i);
    if (angleMatch) {
      return extractRootDomain(angleMatch[1]);
    }

    // 3. Check for bare domain in From header
    const domainMatch = fromVal.match(/\b([A-Z0-9.-]+\.[A-Z]{2,})\b/i);
    if (domainMatch) {
      return extractRootDomain(domainMatch[1]);
    }

    return null;
  }

  const KNOWN_SECOND_LEVEL_TLDS = new Set([
    "co", "com", "net", "org", "edu", "gov", "govt", "gob", "ac", "ne",
    "or", "qc", "gc", "ltd", "plc", "res", "gen", "nom", "biz", "info",
  ]);

  const SENSITIVE_ACTIONS = [
    "/login",
    "/signin",
    "/auth",
    "/verify",
    "/portal",
    "/update",
    "/reset",
  ];

  function extractRootDomain(input) {
    if (!input) return null;
    let str = String(input).trim().toLowerCase();

    // Clean surrounding brackets, quotes, punctuation
    str = str.replace(/^[<("'\s]+|[>) "'\s]+$/g, "");

    // If an email address, extract domain part
    if (str.includes("@")) {
      str = str.split("@").pop().trim();
    }

    // Strip trailing brackets or punctuation after splitting
    str = str.replace(/[>)"'\s]+$/g, "");

    // If URL, parse host
    if (str.includes("://") || str.startsWith("//")) {
      try {
        const u = new URL(str.startsWith("//") ? "http:" + str : str);
        str = u.hostname;
      } catch (e) {
        str = str.replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0];
      }
    } else {
      str = str.split(/[/?#]/)[0];
    }

    // Strip port, www., and trailing dots
    str = str.replace(/:\d+$/, "");
    str = str.replace(/^www\./, "");
    str = str.replace(/\.+$/, "");

    if (!str) return null;

    // IPv4 check
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(str)) {
      return str;
    }

    const parts = str.split(".").filter(Boolean);
    if (parts.length <= 2) {
      return parts.join(".");
    }

    const last = parts[parts.length - 1];
    const secondLast = parts[parts.length - 2];

    // Check multi-part ccTLD public suffixes (e.g. .co.uk, .com.au, .example.net)
    if (last.length === 2 && KNOWN_SECOND_LEVEL_TLDS.has(secondLast)) {
      return parts.slice(-3).join(".");
    }

    return parts.slice(-2).join(".");
  }

  function getSensitiveActionMatch(url) {
    if (!url) return null;
    try {
      const u = new URL(url);
      const path = u.pathname.toLowerCase();
      const search = u.search.toLowerCase();

      for (const action of SENSITIVE_ACTIONS) {
        // Check path
        if (path.includes(action)) return action;

        const kw = action.replace(/^\//, "");
        // Check query string
        if (search.includes(action)) return action;

        // Check query parameters (keys and values)
        for (const [key, val] of u.searchParams.entries()) {
          const k = key.toLowerCase();
          const v = val.toLowerCase();
          if (k === kw || new RegExp(`(^|[^a-z0-9])${kw}([^a-z0-9]|$)`, "i").test(k)) {
            return action;
          }
          if (v === kw || v.includes(action) || new RegExp(`(^|[^a-z0-9])${kw}([^a-z0-9]|$)`, "i").test(v)) {
            return action;
          }
        }
      }
    } catch (e) {
      const lower = String(url).toLowerCase();
      for (const action of SENSITIVE_ACTIONS) {
        if (lower.includes(action)) return action;
      }
    }
    return null;
  }

  function isInsecureHttp(url) {
    return /^http:\/\//i.test(String(url || "").trim());
  }

  function extractUrl(value) {
    const match = String(value).match(/https?:\/\/[^\s<>"']+/i);
    return match ? match[0] : null;
  }

  function hostOf(url) {
    try {
      return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
    } catch (err) {
      return null;
    }
  }

  function urlsLikelyDiffer(a, b) {
    const hostA = hostOf(a);
    const hostB = hostOf(b);
    if (!hostA || !hostB) return false;
    return hostA !== hostB;
  }

  function truncate(value, max) {
    const str = String(value || "");
    return str.length > max ? str.slice(0, max - 1) + "…" : str;
  }

  function parseEmailHeaders(text) {
    const from = extractHeaderValue(text, "From");
    const replyTo = extractHeaderValue(text, "Reply-To") || extractHeaderValue(text, "Reply To");
    const to = extractHeaderValue(text, "To");
    const subject = extractHeaderValue(text, "Subject");
    const date = extractHeaderValue(text, "Date");

    const fromEmail = from ? extractHeaderEmail(text, "From") : null;
    const replyEmail = replyTo ? (extractHeaderEmail(text, "Reply-To") || extractHeaderEmail(text, "Reply To")) : null;

    let mismatch = false;
    if (fromEmail && replyEmail) {
      const fd = domainOf(fromEmail);
      const rd = domainOf(replyEmail);
      if (fd && rd && fd !== rd) mismatch = true;
    }

    if (!from && !replyTo && !to && !subject) {
      return null;
    }

    const fromRootDomain = extractSenderRootDomain(text, from);

    return {
      from,
      replyTo,
      to,
      subject,
      date,
      fromEmail,
      replyEmail,
      fromRootDomain,
      hasMismatch: mismatch,
    };
  }

  function extractAllLinks(text, senderRootDomain) {
    const urls = new Set();
    const linkItems = [];

    function addLink(rawUrl, anchor) {
      if (!rawUrl) return;
      let cleanUrl = rawUrl.trim().replace(/[.,;:)>\]"']+$/, "");
      cleanUrl = cleanUrl.replace(/^[<(\["']+|[>)\]"']+$/g, "");
      if (!cleanUrl || !/^https?:\/\//i.test(cleanUrl)) return;
      if (urls.has(cleanUrl)) return;
      urls.add(cleanUrl);

      const rootDomain = extractRootDomain(cleanUrl);
      const sensitiveAction = getSensitiveActionMatch(cleanUrl);
      const isInsecure = isInsecureHttp(cleanUrl);
      const isMismatch = senderRootDomain ? (rootDomain && rootDomain !== senderRootDomain) : false;

      linkItems.push({
        url: cleanUrl,
        anchor: anchor || "",
        domain: hostOf(cleanUrl) || "Unknown",
        rootDomain: rootDomain || "Unknown",
        isInsecure,
        hasSensitivePath: !!sensitiveAction,
        sensitiveAction,
        isDomainMismatch: isMismatch,
        isIp: /(?:\d{1,3}\.){3}\d{1,3}/.test(cleanUrl),
        isShortened: /(bit\.ly|tinyurl|t\.co|goo\.gl|cutt\.ly|shorturl)/i.test(cleanUrl),
        isSuspiciousTld: /\.(xyz|top|icu|click|country|gq|tk|ml|cf|zip|mov)\b/i.test(cleanUrl),
      });
    }

    // Markdown links
    const mdMatches = [...text.matchAll(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/gi)];
    for (const m of mdMatches) {
      addLink(m[2], m[1]);
    }

    // HTML links
    const htmlMatches = [...text.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)<\/a>/gis)];
    for (const m of htmlMatches) {
      addLink(m[1], m[2].replace(/<[^>]+>/g, "").trim());
    }

    // Raw links
    const rawMatches = [...text.matchAll(/\bhttps?:\/\/[^\s<>"')\]]+/gi)];
    for (const m of rawMatches) {
      addLink(m[0], "");
    }

    return linkItems;
  }

  function analyseEmail(rawText) {
    const text = String(rawText || "");
    const headers = parseEmailHeaders(text);
    const senderEmail = headers ? headers.fromEmail : extractHeaderEmail(text, "From");
    const senderRootDomain = (headers && headers.fromRootDomain) ? headers.fromRootDomain : extractSenderRootDomain(text);
    const senderDomain = (headers && headers.fromRootDomain) ? headers.fromRootDomain : (senderEmail ? domainOf(senderEmail) : null);
    const links = extractAllLinks(text, senderRootDomain);

    const context = {
      headers,
      senderEmail,
      senderDomain,
      senderRootDomain,
      links,
      text,
    };

    const findings = [];

    for (const rule of RULES) {
      let result = { matched: false, evidence: "" };

      if (typeof rule.test === "function") {
        result = rule.test(text, context);
      } else if (rule.patterns) {
        for (const pattern of rule.patterns) {
          const match = text.match(pattern);
          if (match) {
            // Avoid false positives like "no urgent action" or "without penalty"
            if (rule.id === "urgency" || rule.id === "CoerciveConsequence") {
              const idx = match.index || 0;
              const before = text.slice(Math.max(0, idx - 8), idx).toLowerCase();
              if (/\b(no|without)\s+$/i.test(before)) {
                continue;
              }
            }
            result = { matched: true, evidence: truncate(match[0], 90) };
            break;
          }
        }
      }

      if (result && result.matched) {
        findings.push({
          id: rule.id,
          category: rule.category,
          title: rule.title,
          severity: rule.severity,
          points: rule.points,
          explanation: rule.explanation,
          evidence: result.evidence || "",
          metadata: result.metadata || null,
        });
      }
    }

    const rawScore = findings.reduce((sum, item) => sum + item.points, 0);
    const score = Math.min(100, rawScore);
    const classification = classify(score);

    return {
      score,
      rawScore,
      classification,
      findings,
      headers,
      links,
      recommendations: buildRecommendations(score, findings, headers),
    };
  }

  function classify(score) {
    if (score >= 60) {
      return {
        key: "high",
        level: "High Risk",
        badge: "CRITICAL THREAT",
        summary: "Multiple high-confidence phishing indicators identified. High probability of malicious intent.",
      };
    }
    if (score >= 30) {
      return {
        key: "suspicious",
        level: "Suspicious",
        badge: "POTENTIAL RISK",
        summary: "Moderate threat signals detected. Verify independently before opening links or replying.",
      };
    }
    return {
      key: "low",
      level: "Low Risk",
      badge: "CLEAN / LOW RISK",
      summary: "No prominent heuristic red flags matched. Maintain standard operational awareness.",
    };
  }

  function buildRecommendations(score, findings, headers) {
    const recs = [];
    const ids = new Set(findings.map((f) => f.id));

    if (score >= 60) {
      recs.push({
        priority: "Immediate",
        text: "Do not click links, open attachments, or reply. Doing so confirms your inbox is monitored.",
      });
      recs.push({
        priority: "Action",
        text: "Report the message using your email client's 'Report Phishing' tool to alert internal security.",
      });
    } else if (score >= 30) {
      recs.push({
        priority: "Verify",
        text: "Contact the purported sender out-of-band via phone, Slack/Teams, or a known intranet contact.",
      });
      recs.push({
        priority: "Caution",
        text: "If prompted to sign in, navigate to the official website directly by typing the domain manually.",
      });
    } else {
      recs.push({
        priority: "Standard",
        text: "Always verify unexpected payment requests, bank changes, or credential prompts even in clean-looking emails.",
      });
    }

    if (ids.has("SenderLinkDomainMismatch")) {
      recs.push({
        priority: "Domain Spoof",
        text: "Destination link root domain does not match the sender's domain. Never enter organizational credentials or sensitive info on third-party domains.",
      });
    }

    if (ids.has("SensitiveActionUrl")) {
      recs.push({
        priority: "Credential Safety",
        text: "Sensitive authentication/portal link detected on an external domain. Access company systems only via verified bookmarks or direct SSO.",
      });
    }

    if (ids.has("InsecureProtocolLink")) {
      recs.push({
        priority: "Insecure Link",
        text: "Detected unencrypted HTTP link. Legitimate corporate authentication and login services strictly require HTTPS encryption.",
      });
    }

    if (ids.has("CoerciveConsequence")) {
      recs.push({
        priority: "Policy / Coercion",
        text: "Email uses coercive threats (e.g., access revocation or penalties) to bypass scrutiny. Verify with HR or IT security out-of-band before taking action.",
      });
    }

    if (ids.has("password_request") || ids.has("mfa_request") || ids.has("credential_harvest")) {
      recs.push({
        priority: "Credentials",
        text: "Never provide passwords, 2FA tokens, or PINs via email or unverified landing pages.",
      });
    }

    if (ids.has("payment_giftcard") || ids.has("bank_details") || ids.has("invoice_bec")) {
      recs.push({
        priority: "Financial",
        text: "Require secondary verbal confirmation with the finance department before modifying any wire or routing info.",
      });
    }

    if (headers && headers.hasMismatch) {
      recs.push({
        priority: "Headers",
        text: `Sender domain (@${domainOf(headers.fromEmail)}) does not match reply destination (@${domainOf(headers.replyEmail)}). Replies will be redirected.`,
      });
    }

    return recs;
  }

  function generateReportText(result) {
    const lines = [];
    lines.push("========================================");
    lines.push("EMAIL THREAT ASSESSMENT REPORT");
    lines.push("========================================");
    lines.push(`Verdict:     ${result.classification.badge} (${result.classification.level})`);
    lines.push(`Score:       ${result.score} / 100`);
    lines.push(`Assessment:  ${result.classification.summary}`);
    lines.push("");

    if (result.headers) {
      lines.push("--- SENDER & HEADER METADATA ---");
      if (result.headers.from) lines.push(`From:          ${result.headers.from}`);
      if (result.headers.fromRootDomain) lines.push(`Sender Domain: ${result.headers.fromRootDomain}`);
      if (result.headers.replyTo) {
        lines.push(`Reply-To:      ${result.headers.replyTo} ${result.headers.hasMismatch ? "[MISMATCH DETECTED]" : ""}`);
      }
      if (result.headers.subject) lines.push(`Subject:       ${result.headers.subject}`);
      lines.push("");
    }

    lines.push(`--- DETECTED INDICATORS (${result.findings.length}) ---`);
    if (result.findings.length === 0) {
      lines.push("No heuristic threat indicators triggered.");
    } else {
      result.findings.forEach((f, idx) => {
        lines.push(`${idx + 1}. [${f.severity.toUpperCase()}] ${f.title} (+${f.points} pts)`);
        lines.push(`   Category: ${f.category}`);
        lines.push(`   Detail:   ${f.explanation}`);
        if (f.evidence) lines.push(`   Matched:  "${f.evidence}"`);
        lines.push("");
      });
    }

    if (result.links && result.links.length > 0) {
      lines.push(`--- EXTRACTED DESTINATIONS (${result.links.length}) ---`);
      result.links.forEach((l, idx) => {
        const flags = [];
        if (l.isDomainMismatch) flags.push("DOMAIN MISMATCH");
        if (l.hasSensitivePath) flags.push("SENSITIVE ACTION");
        if (l.isInsecure) flags.push("INSECURE HTTP");
        if (l.isIp) flags.push("RAW IP");
        if (l.isShortened) flags.push("SHORTENED");
        if (l.isSuspiciousTld) flags.push("HIGH-RISK TLD");
        const flagStr = flags.length ? ` [${flags.join(", ")}]` : "";
        lines.push(`${idx + 1}. ${l.url}${flagStr}`);
        if (l.rootDomain && l.rootDomain !== "Unknown") lines.push(`   Root Domain:      ${l.rootDomain}`);
        if (l.isDomainMismatch && result.headers && result.headers.fromRootDomain) {
          lines.push(`   Domain Alignment: MISMATCH (Sender: "${result.headers.fromRootDomain}" vs Target: "${l.rootDomain}")`);
        }
        if (l.sensitiveAction) lines.push(`   Sensitive Action: "${l.sensitiveAction}"`);
        if (l.isInsecure) lines.push(`   Protocol:         HTTP (Unencrypted)`);
      });
      lines.push("");
    }

    lines.push("--- RECOMMENDED MITIGATION ---");
    result.recommendations.forEach((r, idx) => {
      lines.push(`${idx + 1}. [${r.priority}] ${r.text}`);
    });
    lines.push("");
    lines.push("Generated locally by MalSense Lab Client Engine.");
    return lines.join("\n");
  }

  // UI Controller
  let currentResult = null;

  function renderDemoButtons() {
    const host = document.getElementById("demo-buttons");
    if (!host || !window.DEMO_EMAILS) return;

    host.innerHTML = "";
    window.DEMO_EMAILS.forEach((demo) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "sample-chip";
      btn.innerHTML = `<span class="chip-label">${escapeHtml(demo.label)}</span><span class="chip-badge">${escapeHtml(demo.badge || "Sample")}</span>`;
      btn.addEventListener("click", () => {
        const input = document.getElementById("email-input");
        input.value = demo.content;
        updateInputStats();
        input.focus();
        runAnalysis();
      });
      host.appendChild(btn);
    });
  }

  function updateInputStats() {
    const input = document.getElementById("email-input");
    const countEl = document.getElementById("char-count");
    if (!input || !countEl) return;
    const len = input.value.length;
    const lines = input.value ? input.value.split("\n").length : 0;
    countEl.textContent = `${len.toLocaleString()} chars • ${lines} lines`;
  }

  function runAnalysis() {
    const input = document.getElementById("email-input");
    const text = input.value.trim();

    if (!text) {
      input.focus();
      input.classList.add("input-pulse-warning");
      setTimeout(() => input.classList.remove("input-pulse-warning"), 1000);
      return;
    }

    currentResult = analyseEmail(text);
    showResults(currentResult);
  }

  function showResults(result) {
    const resultsPanel = document.getElementById("results-panel");
    const emptyState = document.getElementById("empty-state");
    const scoreVal = document.getElementById("score-val");
    const riskBadge = document.getElementById("risk-badge");
    const riskSummary = document.getElementById("risk-summary");
    const scoreMeterFill = document.getElementById("score-meter-fill");
    const statFlags = document.getElementById("stat-flags");
    const statLinks = document.getElementById("stat-links");
    const statHeaders = document.getElementById("stat-headers");
    const headerInspectSection = document.getElementById("header-inspect-section");
    const headerDetails = document.getElementById("header-details");
    const findingsList = document.getElementById("findings-list");
    const emptyFindings = document.getElementById("empty-findings");
    const linksSection = document.getElementById("links-section");
    const linksList = document.getElementById("links-list");
    const recsList = document.getElementById("recommendations-list");

    emptyState.hidden = true;
    resultsPanel.hidden = false;

    // Verdict card
    resultsPanel.setAttribute("data-risk", result.classification.key);
    scoreVal.textContent = String(result.score);
    riskBadge.textContent = result.classification.badge;
    riskBadge.className = `verdict-badge verdict-${result.classification.key}`;
    riskSummary.textContent = result.classification.summary;

    // Meter animation
    scoreMeterFill.style.width = `${Math.min(100, Math.max(3, result.score))}%`;
    scoreMeterFill.className = `meter-fill meter-${result.classification.key}`;

    // Stats
    statFlags.textContent = `${result.findings.length}`;
    statLinks.textContent = `${result.links.length}`;
    if (result.headers) {
      statHeaders.textContent = result.headers.hasMismatch ? "Mismatch" : "Parsed";
      statHeaders.className = result.headers.hasMismatch ? "stat-num text-danger" : "stat-num text-safe";
    } else {
      statHeaders.textContent = "Body Only";
      statHeaders.className = "stat-num text-muted";
    }

    // Headers inspection section
    if (result.headers) {
      headerInspectSection.hidden = false;
      headerDetails.innerHTML = "";

      const entries = [
        { label: "From", val: result.headers.from || "—", warn: false },
        ...(result.headers.fromRootDomain ? [{ label: "Domain", val: result.headers.fromRootDomain, warn: false }] : []),
        {
          label: "Reply-To",
          val: result.headers.replyTo || "(None specified)",
          warn: result.headers.hasMismatch,
          warnText: result.headers.hasMismatch ? "Redirects to different domain" : "",
        },
        { label: "Subject", val: result.headers.subject || "(No subject)", warn: false },
      ];

      entries.forEach((e) => {
        const row = document.createElement("div");
        row.className = "header-row" + (e.warn ? " header-row-warning" : "");
        row.innerHTML = `
          <span class="header-key">${escapeHtml(e.label)}</span>
          <span class="header-val">${escapeHtml(e.val)}</span>
          ${e.warn ? `<span class="header-warn-tag">${escapeHtml(e.warnText)}</span>` : ""}
        `;
        headerDetails.appendChild(row);
      });
    } else {
      headerInspectSection.hidden = true;
    }

    // Findings
    findingsList.innerHTML = "";
    if (result.findings.length === 0) {
      emptyFindings.hidden = false;
    } else {
      emptyFindings.hidden = true;
      result.findings
        .slice()
        .sort((a, b) => b.points - a.points)
        .forEach((f) => {
          const card = document.createElement("div");
          card.className = "ioc-card";
          card.innerHTML = `
            <div class="ioc-head">
              <div class="ioc-meta">
                <span class="severity-pill severity-${f.severity.toLowerCase()}">${escapeHtml(f.severity)}</span>
                <span class="ioc-category">${escapeHtml(f.category)}</span>
              </div>
              <span class="ioc-points">+${f.points} pts</span>
            </div>
            <h4 class="ioc-title">${escapeHtml(f.title)}</h4>
            <p class="ioc-desc">${escapeHtml(f.explanation)}</p>
            ${f.evidence ? `<div class="ioc-evidence"><code>${escapeHtml(f.evidence)}</code></div>` : ""}
          `;
          findingsList.appendChild(card);
        });
    }

    // Extracted links
    if (result.links.length > 0) {
      linksSection.hidden = false;
      linksList.innerHTML = "";
      result.links.forEach((l) => {
        const row = document.createElement("div");
        row.className = "link-item";

        const tags = [];
        if (l.isDomainMismatch) tags.push('<span class="tag-flag tag-danger">Domain Mismatch</span>');
        if (l.hasSensitivePath) tags.push('<span class="tag-flag tag-danger">Sensitive Action</span>');
        if (l.isInsecure) tags.push('<span class="tag-flag tag-warning">Insecure HTTP</span>');
        if (l.isIp) tags.push('<span class="tag-flag tag-danger">Direct IP</span>');
        if (l.isShortened) tags.push('<span class="tag-flag tag-warning">Shortener</span>');
        if (l.isSuspiciousTld) tags.push('<span class="tag-flag tag-danger">Suspicious TLD</span>');

        row.innerHTML = `
          <div class="link-info">
            <span class="link-domain">${escapeHtml(l.rootDomain && l.rootDomain !== "Unknown" ? l.rootDomain : l.domain)}</span>
            <span class="link-url">${escapeHtml(truncate(l.url, 75))}</span>
          </div>
          <div class="link-tags">${tags.join("")}</div>
        `;
        linksList.appendChild(row);
      });
    } else {
      linksSection.hidden = true;
    }

    // Recommendations
    recsList.innerHTML = "";
    result.recommendations.forEach((r) => {
      const li = document.createElement("li");
      li.className = "rec-row";
      li.innerHTML = `
        <span class="rec-priority-badge">${escapeHtml(r.priority)}</span>
        <span class="rec-text">${escapeHtml(r.text)}</span>
      `;
      recsList.appendChild(li);
    });

    resultsPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function clearAll() {
    currentResult = null;
    const input = document.getElementById("email-input");
    input.value = "";
    updateInputStats();
    document.getElementById("results-panel").hidden = true;
    document.getElementById("empty-state").hidden = false;
    input.focus();
  }

  function copyReport() {
    if (!currentResult) return;
    const text = generateReportText(currentResult);
    navigator.clipboard.writeText(text).then(() => {
      const btn = document.getElementById("copy-report-btn");
      const originalText = btn.innerHTML;
      btn.innerHTML = `✓ Copied`;
      btn.classList.add("btn-copied");
      setTimeout(() => {
        btn.innerHTML = originalText;
        btn.classList.remove("btn-copied");
      }, 2000);
    }).catch(() => {
      alert("Report copied to clipboard.");
    });
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", () => {
      renderDemoButtons();

      const input = document.getElementById("email-input");
      if (input) {
        input.addEventListener("input", updateInputStats);
        input.addEventListener("keydown", (e) => {
          if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
            e.preventDefault();
            runAnalysis();
          }
        });
      }

      const analyseBtn = document.getElementById("analyse-btn");
      if (analyseBtn) analyseBtn.addEventListener("click", runAnalysis);

      const clearBtn = document.getElementById("clear-btn");
      if (clearBtn) clearBtn.addEventListener("click", clearAll);

      const copyBtn = document.getElementById("copy-report-btn");
      if (copyBtn) copyBtn.addEventListener("click", copyReport);
    });
  }

  const api = {
    analyseEmail,
    RULES,
    classify,
    parseEmailHeaders,
    extractAllLinks,
    extractRootDomain,
    extractSenderRootDomain,
    getSensitiveActionMatch,
    isInsecureHttp,
    detectSenderLinkDomainMismatch,
    detectSensitiveActionUrl,
    detectInsecureProtocolLink,
    buildRecommendations,
    generateReportText,
  };

  if (typeof window !== "undefined") {
    window.PhishingEmailAnalyser = api;
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})();
