/**
 * Fictional test cases for phishing analysis.
 * Safe demonstration data — no active attack vectors or malicious domains.
 */
const DEMO_EMAILS = [
  {
    id: "hr_spearphish",
    label: "HR Policy Spear-Phish",
    badge: "Domain Mismatch",
    content: `From: HR Operations <compliance@internal-corp-portal.com>
Subject: Mandatory Employee Policy Acknowledgment - Immediate Action Required

Dear Team Member,

Please review and acknowledge the updated Employee Remote Work & Acceptable Use Policy immediately.

Failure to complete this acknowledgment will restrict network access.

Review and acknowledge here:
http://phishing-simulation-target.example.net/hr/login

Human Resources Compliance Division
Internal Corporate Services`,
  },
  {
    id: "paypal",
    label: "PayPal Credential Theft",
    badge: "Urgent Phish",
    content: `From: PayPal Security <secure-alerts@paypa1-support.xyz>
Reply-To: recover-now@mail-recover.top
Subject: URGENT: Your account will be suspended in 24 hours

Dear Valued Customer,

Your PayPal account will be suspended immediately unless you verify your identity right now.

Click here to verify: http://bit.ly/paypal-secure-login-demo

You must confirm your password and verification code within 2 hours or access will be revoked.

PayPal Security Team
This is an automated security message.`,
  },
  {
    id: "m365_spoof",
    label: "M365 Link Spoofing",
    badge: "Deceptive Link",
    content: `From: IT Support <it.support@contoso-company.com>
Reply-To: mailbox.review@contoso-security-check.icu
Subject: Action required: mailbox storage validation

Hello,

During a routine compliance review we identified that your mailbox permissions need re-authentication.

Please sign in to avoid service interruption using the secure portal below:
<a href="http://203.0.113.44/account-verify/session">https://outlook.office.com/mail</a>

After signing in, confirm ownership of your mailbox so we can complete the account review.

Kind regards,
IT Helpdesk
Contoso Company`,
  },
  {
    id: "m365_lockout",
    label: "M365 Lockout Alert",
    badge: "Lookalike Domain",
    content: `From: Microsoft 365 <noreply@office365-alerts.xyz>
Subject: Unusual sign-in blocked — unlock your account

Microsoft 365 Security

We blocked a sign-in attempt from an unrecognised location.
Your Office 365 account will be locked unless you unlock your account today.

Click below to verify your account and re-authenticate:
https://secure-login-office365.top/verify-account

If you do not complete verification, access will be revoked.

Outlook Security / Microsoft 365
This is an automated security message.`,
  },
  {
    id: "parcel",
    label: "Courier Delivery Fee",
    badge: "Fee Scam",
    content: `From: ParcelForce Notifications <delivery@parcelforce-redelivery.icu>
Subject: Your parcel could not be delivered — fee due

Hello,

We attempted to deliver your parcel today but no one was available.

To rearrange delivery you must pay a small redelivery fee immediately:
https://cutt.ly/redeliver-parcel-fee-demo

Payment must be completed within 24 hours or your package will be returned to sender.

Tracking ID: PF-DEMO-908812
Parcel Delivery Team`,
  },
  {
    id: "bec_wire",
    label: "CEO Wire Fraud / BEC",
    badge: "Executive Spoof",
    content: `From: Sarah Mitchell (CFO) <sarah.mitchell@northwind-example.com>
Reply-To: s.mitchell.payments@protonmail-demo.example
Subject: Urgent invoice payment — new bank details

Hi,

I need you to process this payment today. Keep this confidential and do not discuss with the wider finance team.

There is an outstanding invoice that must be paid by wire transfer using our new bank details:

Account name: Northwind Holdings Ops
Sort code: 00-00-00
Account number: 12345678

Please update the bank details on file and send payment immediately.
I am in meetings all afternoon, so handle this discreetly.

Thanks,
Sarah Mitchell
CFO

Attachment: Invoice_Payment_Update.zip`,
  },
  {
    id: "legitimate",
    label: "Legitimate Team Sync",
    badge: "Clean Email",
    content: `From: Alex Rivera <alex.rivera@northwind-example.com>
To: team@northwind-example.com
Subject: Notes from Thursday project sync

Hi team,

Thanks for joining the project sync on Thursday. Here are the open actions we agreed:

1. Alex — draft the timeline update by next Wednesday
2. Sam — share the revised checklist in the shared drive
3. Priya — book the follow-up meeting for the week after

No urgent action is needed today. If the Wednesday draft will be delayed, just reply on this thread and we can adjust.

The meeting notes are already in our usual shared folder.

    Best regards,
    Alex Rivera
    Project Coordinator
    Northwind Example Ltd`,
  },
];

if (typeof window !== "undefined") {
  window.DEMO_EMAILS = DEMO_EMAILS;
}
if (typeof module !== "undefined" && module.exports) {
  module.exports = DEMO_EMAILS;
}

