export default function SecurityAwareness() {
  return (
    <div className="fade-up" style={{ maxWidth: 860, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Header */}
      <div>
        <div
          style={{
            display: 'inline-block',
            background: 'linear-gradient(135deg, rgba(102, 126, 234, 0.15), rgba(118, 75, 162, 0.15))',
            color: '#667eea',
            fontSize: 11,
            fontWeight: 800,
            padding: '5px 14px',
            borderRadius: 20,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            marginBottom: 12,
          }}
        >
          Security Awareness & Prevention
        </div>
        <h1
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 'clamp(24px, 3vw, 32px)',
            fontWeight: 800,
            color: '#0f172a',
            margin: '0 0 8px',
            letterSpacing: '-0.02em',
          }}
        >
          Cyber Safety Guide
        </h1>
        <p
          style={{
            fontFamily: 'var(--font-body)',
            fontSize: 15,
            color: '#64748b',
            margin: 0,
            lineHeight: 1.6,
          }}
        >
          Essential guidance on identifying common scams, spotting red flags, and taking immediate action if targeted.
        </p>
      </div>

      {/* Quick Emergency Helplines Callout */}
      <div
        className="card"
        style={{
          padding: '20px 24px',
          background: 'linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%)',
          border: '1.5px solid rgba(99, 102, 241, 0.25)',
          borderRadius: 14,
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 16,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <span style={{ fontSize: 28 }}>🚨</span>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#0f172a', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              National Cybercrime Reporting Helpline
            </div>
            <div style={{ fontSize: 24, fontWeight: 900, color: '#dc2626', fontFamily: 'var(--font-heading)', letterSpacing: '0.02em' }}>
              1930
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <a
            href="https://cybercrime.gov.in"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              background: '#ffffff',
              color: '#6366f1',
              border: '1px solid rgba(99, 102, 241, 0.3)',
              padding: '8px 16px',
              borderRadius: 30,
              fontSize: 13,
              fontWeight: 700,
              textDecoration: 'none',
              boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
            }}
          >
            cybercrime.gov.in ↗
          </a>
          <a
            href="https://sancharsaathi.gov.in/sfc"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              background: '#ffffff',
              color: '#0284c7',
              border: '1px solid rgba(2, 132, 199, 0.3)',
              padding: '8px 16px',
              borderRadius: 30,
              fontSize: 13,
              fontWeight: 700,
              textDecoration: 'none',
              boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
            }}
          >
            Sanchar Saathi (Chakshu) ↗
          </a>
        </div>
      </div>

      {/* Section 1: Common Scams in India */}
      <div className="card" style={{ padding: '24px 28px' }}>
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#0f172a',
            margin: '0 0 12px',
          }}
        >
          1. Common Scams in India
        </h2>
        <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.6, margin: '0 0 12px' }}>
          Be alert to these prevalent scam patterns targeting individuals across communications and payment apps:
        </p>
        <ul style={{ paddingLeft: 20, margin: 0, color: '#334155', fontSize: 14, lineHeight: 1.8 }}>
          <li>
            <strong>Fake job offers:</strong> Unsolicited messages promising high earnings, including work-from-home and "task-based" jobs (e.g. liking videos, rating products).
          </li>
          <li>
            <strong>Fake KYC / bank messages:</strong> Urgent SMS or WhatsApp alerts claiming your bank account, SIM card, or payment app will be blocked unless you click a link or call a number.
          </li>
          <li>
            <strong>Phishing links:</strong> Fraudulent links delivered through SMS or WhatsApp pretending to be legitimate services, lotteries, or government portals.
          </li>
          <li>
            <strong>Payment-request and QR-code tricks:</strong> Scammers sending a "Collect Request" or asking you to scan a QR code under the pretext of sending you money.
          </li>
          <li>
            <strong>Fake customer-care numbers:</strong> Search engine results or fake social profiles posting fraudulent support numbers that connect directly to scammers.
          </li>
          <li>
            <strong>Impersonation of police or investigation agencies:</strong> Scammers posing as police, CBI, customs, or court officials over phone or video calls. <em>"Digital arrest" is a scam: no genuine government agency ever arrests anyone over a video call or demands money to "settle" an investigation.</em>
          </li>
        </ul>
      </div>

      {/* Section 2: Fake Job Offer Red Flags */}
      <div className="card" style={{ padding: '24px 28px' }}>
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#0f172a',
            margin: '0 0 12px',
          }}
        >
          2. Fake Job Offer Red Flags
        </h2>
        <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.6, margin: '0 0 12px' }}>
          Genuine employers never ask candidates to pay for employment. Watch out for these clear warning signs:
        </p>
        <ul style={{ paddingLeft: 20, margin: 0, color: '#334155', fontSize: 14, lineHeight: 1.8 }}>
          <li>
            <strong>Upfront fees:</strong> Any request to pay money for registration, document processing, training materials, onboarding kits, or a "refundable" security deposit.
          </li>
          <li>
            <strong>Unrealistic salary:</strong> Pay offers that are unusually high compared to the minimal effort or experience required.
          </li>
          <li>
            <strong>Informal communication channels:</strong> Recruitment handled exclusively through WhatsApp or Telegram rather than official corporate emails or portals.
          </li>
          <li>
            <strong>High-pressure urgency:</strong> Insistence that you must respond, accept, or transfer fees today or within hours.
          </li>
          <li>
            <strong>No formal interview:</strong> Immediate selection or offer letter issued without any professional evaluation, test, or interview.
          </li>
          <li>
            <strong>Free email addresses:</strong> Recruiter contacting from free public domains (such as Gmail, Yahoo, or Outlook) rather than the company's verified domain.
          </li>
          <li>
            <strong>Vague company details:</strong> Missing physical office address, absence of verified website, or unclear job descriptions.
          </li>
        </ul>
      </div>

      {/* Section 3: Never Share */}
      <div
        className="card"
        style={{
          padding: '24px 28px',
          background: '#fff1f2',
          border: '1.5px solid #fecdd3',
        }}
      >
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#991b1b',
            margin: '0 0 12px',
          }}
        >
          3. Never Share
        </h2>
        <p style={{ fontSize: 14.5, color: '#991b1b', lineHeight: 1.6, margin: '0 0 12px' }}>
          Legitimate banks, government bodies, and platforms will never ask you for confidential authentication credentials:
        </p>
        <ul style={{ paddingLeft: 20, margin: '0 0 16px', color: '#7f1d1d', fontSize: 14, lineHeight: 1.8 }}>
          <li><strong>One-Time Password (OTP)</strong></li>
          <li><strong>UPI PIN</strong></li>
          <li><strong>Card PIN or CVV number</strong></li>
          <li><strong>Account passwords</strong></li>
        </ul>
        <div
          style={{
            background: '#ffffff',
            padding: '12px 16px',
            borderRadius: 10,
            border: '1px solid #fca5a5',
            color: '#b91c1c',
            fontWeight: 700,
            fontSize: 14,
          }}
        >
          💡 Golden Rule: You never need to enter your UPI PIN to receive money. A UPI PIN is only entered when transferring money out of your account.
        </div>
      </div>

      {/* Section 4: Before You Click */}
      <div className="card" style={{ padding: '24px 28px' }}>
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#0f172a',
            margin: '0 0 12px',
          }}
        >
          4. Before You Click
        </h2>
        <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.6, margin: '0 0 12px' }}>
          Malicious links often masquerade as reputable platforms. Practice these verification habits:
        </p>
        <ul style={{ paddingLeft: 20, margin: 0, color: '#334155', fontSize: 14, lineHeight: 1.8 }}>
          <li>
            <strong>Inspect the full domain:</strong> Check the entire web address, not just brand words included in the path or subdomain (e.g. <code>brand-login.fraudsite.com</code> is hosted on <code>fraudsite.com</code>).
          </li>
          <li>
            <strong>Look for lookalike spellings:</strong> Attackers often substitute visually similar characters or numbers (such as using the digit <code>1</code> for the letter <code>l</code> or <code>0</code> for <code>o</code>).
          </li>
          <li>
            <strong>Be cautious with shortened links:</strong> Shortened URLs (like bit.ly, tinyurl) mask the true destination.
          </li>
          <li>
            <strong>Navigate directly:</strong> Always open your browser and navigate to the official website yourself instead of clicking links provided in unsolicited messages.
          </li>
        </ul>
      </div>

      {/* Section 5: If You Have Been Scammed (Steps, in Order) */}
      <div className="card" style={{ padding: '24px 28px' }}>
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#0f172a',
            margin: '0 0 12px',
          }}
        >
          5. If You Have Been Scammed (Steps, in Order)
        </h2>
        <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.6, margin: '0 0 14px' }}>
          If money has been transferred or credentials compromised, follow these exact steps immediately:
        </p>
        <ol style={{ paddingLeft: 22, margin: 0, color: '#334155', fontSize: 14, lineHeight: 1.9 }}>
          <li>
            <strong>Step 1: Contact your bank or payment provider immediately.</strong> Request that your bank account, debit/credit cards, or payment app access be blocked to prevent further unauthorized transactions.
          </li>
          <li>
            <strong>Step 2: Report financial fraud on the national cybercrime helpline or portal.</strong> Call national helpline <strong style={{ color: '#dc2626' }}>1930</strong> immediately, or register a formal incident online at{' '}
            <a
              href="https://cybercrime.gov.in"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: '#6366f1', fontWeight: 700, textDecoration: 'underline' }}
            >
              cybercrime.gov.in ↗
            </a>.
          </li>
          <li>
            <strong>Step 3: Collect and preserve evidence.</strong> Keep full screenshots, transaction IDs (UTR/reference numbers), payment receipts, bank statements, phone numbers, email headers, and message links.
          </li>
          <li>
            <strong>Step 4: Do not delete the chat.</strong> Maintain the complete communication history as unaltered digital evidence for investigating authorities.
          </li>
        </ol>
      </div>

      {/* Section 6: Report Suspicious Messages Before You Lose Money */}
      <div className="card" style={{ padding: '24px 28px' }}>
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#0f172a',
            margin: '0 0 12px',
          }}
        >
          6. Report Suspicious Messages (Before You Lose Money)
        </h2>
        <p style={{ fontSize: 14.5, color: '#334155', lineHeight: 1.7, margin: 0 }}>
          If you encounter suspicious calls, SMS, or WhatsApp messages but have not transferred any money, proactively report the communication through <strong>Chakshu</strong> on the Department of Telecommunications Sanchar Saathi portal at{' '}
          <a
            href="https://sancharsaathi.gov.in/sfc"
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: '#0284c7', fontWeight: 700, textDecoration: 'underline' }}
          >
            sancharsaathi.gov.in/sfc ↗
          </a>.
        </p>
      </div>

      {/* Section 7: Using ScamXRay Responsibly */}
      <div className="card" style={{ padding: '24px 28px' }}>
        <h2
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 18,
            fontWeight: 700,
            color: '#0f172a',
            margin: '0 0 12px',
          }}
        >
          7. Using ScamXRay Responsibly
        </h2>
        <p style={{ fontSize: 14.5, color: '#334155', lineHeight: 1.7, margin: '0 0 10px' }}>
          ScamXRay is an automated threat intelligence tool that analyses message text, web links, and screenshot OCR to explain why a communication appears risky based on known fraud indicators.
        </p>
        <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.7, margin: 0 }}>
          <strong>A verdict of "No threat found" does not guarantee that a link or message is safe.</strong> Attackers continuously register new domains and craft novel deceptive messages. Always verify offers directly with official organisations and never bypass standard safety checks.
        </p>
      </div>
    </div>
  );
}