export default function SecurityAwareness() {
  return (
    <div style={{ maxWidth: 860, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* ─────────────────────────────────────────────────────────────
          PAGE HEADER
      ───────────────────────────────────────────────────────────── */}
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

      {/* ─────────────────────────────────────────────────────────────
          1. COMPACT "IF YOU HAVE BEEN SCAMMED" TOP HELP CARDS (Row of 3)
      ───────────────────────────────────────────────────────────── */}
      <div>
        <div
          style={{
            fontSize: 12,
            fontWeight: 700,
            color: '#64748b',
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            marginBottom: 10,
          }}
        >
          Emergency Help & Reporting
        </div>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 250px), 1fr))',
            gap: 14,
          }}
        >
          {/* Card 1: 1930 */}
          <div
            className="card"
            style={{
              padding: '18px 20px',
              background: '#fff1f2',
              border: '1.5px solid #fecdd3',
              borderRadius: 12,
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: 10,
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 11.5, fontWeight: 700, color: '#991b1b', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  National Helpline
                </span>
                <span style={{ fontSize: 18 }}>🚨</span>
              </div>
              <div style={{ fontSize: 26, fontWeight: 900, color: '#dc2626', fontFamily: 'var(--font-heading)', lineHeight: 1.1, marginBottom: 6 }}>
                1930
              </div>
              <p style={{ fontSize: 12.5, color: '#7f1d1d', margin: 0, lineHeight: 1.5 }}>
                Call national helpline 1930 immediately to report financial fraud and request account freezing.
              </p>
            </div>
            <div style={{ fontSize: 11.5, fontWeight: 700, color: '#b91c1c' }}>
              Toll-Free • 24x7 Assistance
            </div>
          </div>

          {/* Card 2: cybercrime.gov.in */}
          <div
            className="card"
            style={{
              padding: '18px 20px',
              background: '#f8f7ff',
              border: '1.5px solid rgba(99, 102, 241, 0.22)',
              borderRadius: 12,
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: 10,
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 11.5, fontWeight: 700, color: '#4338ca', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Report Online
                </span>
                <span style={{ fontSize: 18 }}>🌐</span>
              </div>
              <div style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', fontFamily: 'var(--font-heading)', marginBottom: 6 }}>
                cybercrime.gov.in
              </div>
              <p style={{ fontSize: 12.5, color: '#475569', margin: 0, lineHeight: 1.5 }}>
                Register a formal financial or cyber fraud complaint on the National Cyber Crime Reporting Portal.
              </p>
            </div>
            <div>
              <a
                href="https://cybercrime.gov.in"
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  color: '#6366f1',
                  fontWeight: 700,
                  fontSize: 12.5,
                  textDecoration: 'none',
                }}
              >
                <span>cybercrime.gov.in</span>
                <span>↗</span>
              </a>
            </div>
          </div>

          {/* Card 3: Sanchar Saathi / Chakshu */}
          <div
            className="card"
            style={{
              padding: '18px 20px',
              background: '#f0f9ff',
              border: '1.5px solid rgba(2, 132, 199, 0.22)',
              borderRadius: 12,
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: 10,
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 11.5, fontWeight: 700, color: '#0369a1', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Suspicious Messages
                </span>
                <span style={{ fontSize: 18 }}>📱</span>
              </div>
              <div style={{ fontSize: 16, fontWeight: 800, color: '#0f172a', fontFamily: 'var(--font-heading)', marginBottom: 6 }}>
                Sanchar Saathi (Chakshu)
              </div>
              <p style={{ fontSize: 12.5, color: '#475569', margin: 0, lineHeight: 1.5 }}>
                Report suspicious calls, SMS or WhatsApp messages before you lose money via Department of Telecommunications.
              </p>
            </div>
            <div>
              <a
                href="https://sancharsaathi.gov.in/sfc"
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  color: '#0284c7',
                  fontWeight: 700,
                  fontSize: 12.5,
                  textDecoration: 'none',
                }}
              >
                <span>sancharsaathi.gov.in/sfc</span>
                <span>↗</span>
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          2. RESPONSIVE CARD GRID (2 Columns on Desktop, 1 on Mobile)
      ───────────────────────────────────────────────────────────── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 380px), 1fr))',
          gap: 20,
        }}
      >
        {/* Card A: Common Scams in India */}
        <div className="card" style={{ padding: '24px 26px', display: 'flex', flexDirection: 'column' }}>
          <h2
            style={{
              fontFamily: 'var(--font-heading)',
              fontSize: 17,
              fontWeight: 700,
              color: '#0f172a',
              margin: '0 0 10px',
            }}
          >
            1. Common Scams in India
          </h2>
          <p style={{ fontSize: 13.5, color: '#64748b', lineHeight: 1.6, margin: '0 0 12px' }}>
            Be alert to these prevalent scam patterns targeting individuals across communications and payment apps:
          </p>
          <ul style={{ paddingLeft: 18, margin: 0, color: '#334155', fontSize: 13.5, lineHeight: 1.75 }}>
            <li>
              <strong>Fake job offers:</strong> Unsolicited messages promising high earnings, including work-from-home and &quot;task-based&quot; jobs (e.g. liking videos, rating products).
            </li>
            <li>
              <strong>Fake KYC / bank messages:</strong> Urgent SMS or WhatsApp alerts claiming your bank account, SIM card, or payment app will be blocked unless you click a link or call a number.
            </li>
            <li>
              <strong>Phishing links:</strong> Fraudulent links delivered through SMS or WhatsApp pretending to be legitimate services, lotteries, or government portals.
            </li>
            <li>
              <strong>Payment-request and QR-code tricks:</strong> Scammers sending a &quot;Collect Request&quot; or asking you to scan a QR code under the pretext of sending you money.
            </li>
            <li>
              <strong>Fake customer-care numbers:</strong> Search engine results or fake social profiles posting fraudulent support numbers that connect directly to scammers.
            </li>
            <li>
              <strong>Impersonation of police or investigation agencies:</strong> Scammers posing as police, CBI, customs, or court officials over phone or video calls. <em>&quot;Digital arrest&quot; is a scam: no genuine government agency ever arrests anyone over a video call or demands money to &quot;settle&quot; an investigation.</em>
            </li>
          </ul>
        </div>

        {/* Card B: Fake Job Offer Red Flags */}
        <div className="card" style={{ padding: '24px 26px', display: 'flex', flexDirection: 'column' }}>
          <h2
            style={{
              fontFamily: 'var(--font-heading)',
              fontSize: 17,
              fontWeight: 700,
              color: '#0f172a',
              margin: '0 0 10px',
            }}
          >
            2. Fake Job Offer Red Flags
          </h2>
          <p style={{ fontSize: 13.5, color: '#64748b', lineHeight: 1.6, margin: '0 0 12px' }}>
            Genuine employers never ask candidates to pay for employment. Watch out for these clear warning signs:
          </p>
          <ul style={{ paddingLeft: 18, margin: 0, color: '#334155', fontSize: 13.5, lineHeight: 1.75 }}>
            <li>
              <strong>Upfront fees:</strong> Any request to pay money for registration, document processing, training materials, onboarding kits, or a &quot;refundable&quot; security deposit.
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
              <strong>Free email addresses:</strong> Recruiter contacting from free public domains (such as Gmail, Yahoo, or Outlook) rather than the company&apos;s verified domain.
            </li>
            <li>
              <strong>Vague company details:</strong> Missing physical office address, absence of verified website, or unclear job descriptions.
            </li>
          </ul>
        </div>

        {/* Card C: Never Share */}
        <div
          className="card"
          style={{
            padding: '24px 26px',
            background: '#fff1f2',
            border: '1.5px solid #fecdd3',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          <h2
            style={{
              fontFamily: 'var(--font-heading)',
              fontSize: 17,
              fontWeight: 700,
              color: '#991b1b',
              margin: '0 0 10px',
            }}
          >
            3. Never Share
          </h2>
          <p style={{ fontSize: 13.5, color: '#991b1b', lineHeight: 1.6, margin: '0 0 12px' }}>
            Legitimate banks, government bodies, and platforms will never ask you for confidential authentication credentials:
          </p>
          <ul style={{ paddingLeft: 18, margin: '0 0 16px', color: '#7f1d1d', fontSize: 13.5, lineHeight: 1.75 }}>
            <li><strong>One-Time Password (OTP)</strong></li>
            <li><strong>UPI PIN</strong></li>
            <li><strong>Card PIN or CVV number</strong></li>
            <li><strong>Account passwords</strong></li>
          </ul>
          <div
            style={{
              background: '#ffffff',
              padding: '12px 14px',
              borderRadius: 8,
              border: '1px solid #fca5a5',
              color: '#b91c1c',
              fontWeight: 700,
              fontSize: 13,
              lineHeight: 1.5,
            }}
          >
            💡 Golden Rule: You never need to enter your UPI PIN to receive money. A UPI PIN is only entered when transferring money out of your account.
          </div>
        </div>

        {/* Card D: Before You Click */}
        <div className="card" style={{ padding: '24px 26px', display: 'flex', flexDirection: 'column' }}>
          <h2
            style={{
              fontFamily: 'var(--font-heading)',
              fontSize: 17,
              fontWeight: 700,
              color: '#0f172a',
              margin: '0 0 10px',
            }}
          >
            4. Before You Click
          </h2>
          <p style={{ fontSize: 13.5, color: '#64748b', lineHeight: 1.6, margin: '0 0 12px' }}>
            Malicious links often masquerade as reputable platforms. Practice these verification habits:
          </p>
          <ul style={{ paddingLeft: 18, margin: 0, color: '#334155', fontSize: 13.5, lineHeight: 1.75 }}>
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
      </div>

      {/* ─────────────────────────────────────────────────────────────
          3. FULL-WIDTH CARD: IF YOU HAVE BEEN SCAMMED (Steps, in Order)
      ───────────────────────────────────────────────────────────── */}
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

      {/* ─────────────────────────────────────────────────────────────
          4. FULL-WIDTH CARD: USING SCAMXRAY RESPONSIBLY
      ───────────────────────────────────────────────────────────── */}
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
          6. Using ScamXRay Responsibly
        </h2>
        <p style={{ fontSize: 14.5, color: '#334155', lineHeight: 1.7, margin: '0 0 10px' }}>
          ScamXRay is an automated threat intelligence tool that analyses message text, web links, and screenshot OCR to explain why a communication appears risky based on known fraud indicators.
        </p>
        <p style={{ fontSize: 14.5, color: '#475569', lineHeight: 1.7, margin: 0 }}>
          <strong>A verdict of &quot;No threat found&quot; does not guarantee that a link or message is safe.</strong> Attackers continuously register new domains and craft novel deceptive messages. Always verify offers directly with official organisations and never bypass standard safety checks.
        </p>
      </div>
    </div>
  );
}
