import { useLocation, useNavigate } from 'react-router-dom';

const FONT = "'DM Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";
const HEADING_FONT = "'Manrope', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";

const COLORS = {
  primary: '#4f46e5',
  primaryDark: '#3730a3',
  primaryLight: '#eeefff',
  text: '#0f172a',
  muted: '#64748b',
  border: '#e2e8f0',
  background: '#f8f7ff',
  green: '#16a34a',
  greenBg: '#f0fdf4',
  greenBorder: '#bbf7d0',
  amber: '#d97706',
  amberBg: '#fffbeb',
  amberBorder: '#fde68a',
  red: '#dc2626',
  redBg: '#fef2f2',
  redBorder: '#fecaca',
  blue: '#2563eb',
  blueBg: '#eff6ff',
  blueBorder: '#bfdbfe',
  slate: '#475569',
  slateBg: '#f8fafc',
  slateBorder: '#cbd5e1',
};

function normalizeScore(value) {
  if (value === null || value === undefined || value === '') return null;
  const score = Number(value);
  if (!Number.isFinite(score)) return null;
  return Math.max(0, Math.min(100, Math.round(score)));
}

function getRiskLevel(score) {
  if (score <= 30) return 'LOW';
  if (score <= 70) return 'MEDIUM';
  return 'HIGH';
}

function getRiskColor(level) {
  if (level === 'LOW') return COLORS.green;
  if (level === 'MEDIUM') return COLORS.amber;
  if (level === 'UNVERIFIED') return COLORS.slate;
  return COLORS.red;
}

function formatLabel(value) {
  return String(value || 'Unclassified')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function getFlagText(flag) {
  if (typeof flag === 'string') return flag;
  return (
    flag?.text ||
    flag?.message ||
    flag?.description ||
    flag?.name ||
    'Potential threat indicator'
  );
}

function getTipText(tip) {
  if (typeof tip === 'string') return tip;
  return tip?.text || tip?.message || tip?.description || '';
}

function Panel({ title, icon, badge, children, style = {} }) {
  return (
    <section
      style={{
        background: '#ffffff',
        border: `1px solid ${COLORS.border}`,
        borderRadius: 16,
        padding: '24px clamp(18px, 2.5vw, 28px)',
        boxShadow: '0 4px 20px rgba(79, 70, 229, 0.04)',
        minWidth: 0,
        ...style,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 10,
          margin: '0 0 18px',
        }}
      >
        <h2
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            fontSize: 17,
            fontWeight: 800,
            fontFamily: HEADING_FONT,
            margin: 0,
            color: COLORS.text,
            letterSpacing: '-0.01em',
          }}
        >
          {icon && <span style={{ fontSize: 18 }}>{icon}</span>}
          {title}
        </h2>
        {badge && <div>{badge}</div>}
      </div>

      {children}
    </section>
  );
}

function CircularScoreGauge({ score, color, size = 140, strokeWidth = 10, label = 'OUT OF 100', displayText }) {
  const isOverride = Boolean(displayText);
  const safeScore = Math.max(0, Math.min(100, Math.round(score ?? 0)));
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = isOverride ? circumference : circumference - (safeScore / 100) * circumference;

  return (
    <div
      style={{
        position: 'relative',
        width: size,
        height: size,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexShrink: 0,
      }}
    >
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        style={{ transform: 'rotate(-90deg)', overflow: 'visible' }}
      >
        {/* Track circle */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="#ffffff"
          stroke="#e2e8f0"
          strokeWidth={strokeWidth}
        />
        {/* Progress stroke */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap={safeScore >= 100 ? 'butt' : 'round'}
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
      </svg>

      <div
        style={{
          position: 'absolute',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          textAlign: 'center',
          pointerEvents: 'none',
          padding: '0 8px',
        }}
      >
        <span
          style={{
            color: color,
            fontSize: isOverride ? 18 : size > 120 ? 38 : 28,
            fontWeight: 850,
            fontFamily: HEADING_FONT,
            lineHeight: 1.1,
            letterSpacing: isOverride ? '-0.01em' : 'normal',
          }}
        >
          {displayText ?? safeScore}
        </span>
        <span
          style={{
            color: COLORS.muted,
            fontSize: 10,
            fontWeight: 800,
            letterSpacing: '0.06em',
            marginTop: 4,
          }}
        >
          {label}
        </span>
      </div>
    </div>
  );
}

function ScoreCard({ title, score, subtitle, isAvailable = true, displayText }) {
  const safeScore = normalizeScore(score);
  const displayScore = safeScore ?? 0;
  const level = getRiskLevel(displayScore);
  const color = !isAvailable || (safeScore === null && !displayText) ? '#94a3b8' : displayText ? COLORS.slate : getRiskColor(level);

  return (
    <div
      style={{
        minWidth: 0,
        padding: '16px 18px',
        border: `1px solid ${COLORS.border}`,
        borderRadius: 14,
        background: '#ffffff',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
      }}
    >
      <div>
        <p
          style={{
            color: COLORS.muted,
            fontSize: 11,
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '0.06em',
            margin: '0 0 10px',
          }}
        >
          {title}
        </p>

        <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
          <strong
            style={{
              color: color,
              fontSize: displayText ? 20 : 28,
              fontWeight: 850,
              fontFamily: HEADING_FONT,
            }}
          >
            {displayText ? displayText : !isAvailable || safeScore === null ? 'N/A' : safeScore}
          </strong>
          {isAvailable && safeScore !== null && !displayText && (
            <span style={{ color: '#94a3b8', fontSize: 12, fontWeight: 600 }}>/100</span>
          )}
        </div>
      </div>

      <div style={{ marginTop: 14 }}>
        <div
          style={{
            height: 6,
            background: '#f1f5f9',
            borderRadius: 10,
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              height: '100%',
              width: !isAvailable || safeScore === null || displayText ? '0%' : `${displayScore}%`,
              background: color,
              borderRadius: 10,
              transition: 'width 0.4s ease',
            }}
          />
        </div>
        <p style={{ color: '#94a3b8', fontSize: 11, margin: '6px 0 0', fontWeight: 500 }}>
          {subtitle || (!isAvailable ? 'Not evaluated' : `${level} severity`)}
        </p>
      </div>
    </div>
  );
}

function RiskRadar({ axes = [] }) {
  if (!axes || axes.length < 3) return null;
  const count = axes.length;
  const labels = axes.map((a) => a.label);
  const scores = axes.map((a) => normalizeScore(a.value) ?? 0);

  const getPoint = (score, index, maxRadius = 68) => {
    const angle = (-90 + (index * 360) / count) * (Math.PI / 180);
    const radius = (maxRadius * score) / 100;
    return {
      x: 100 + Math.cos(angle) * radius,
      y: 100 + Math.sin(angle) * radius,
    };
  };

  const points = scores
    .map((score, index) => {
      const point = getPoint(score, index);
      return `${point.x},${point.y}`;
    })
    .join(' ');

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexWrap: 'wrap',
        gap: 18,
      }}
    >
      <svg
        viewBox="0 0 200 200"
        role="img"
        aria-label="Risk radar chart"
        style={{ width: 190, maxWidth: '100%' }}
      >
        {[17, 34, 51, 68].map((radius) => (
          <polygon
            key={radius}
            points={labels
              .map((_, index) => {
                const angle = (-90 + (index * 360) / count) * (Math.PI / 180);
                return `${100 + Math.cos(angle) * radius},${100 + Math.sin(angle) * radius}`;
              })
              .join(' ')}
            fill="none"
            stroke="#e2e8f0"
            strokeWidth="1"
          />
        ))}

        {labels.map((label, index) => {
          const angle = (-90 + (index * 360) / count) * (Math.PI / 180);
          return (
            <line
              key={label}
              x1="100"
              y1="100"
              x2={100 + Math.cos(angle) * 68}
              y2={100 + Math.sin(angle) * 68}
              stroke="#e2e8f0"
            />
          );
        })}

        <polygon
          points={points}
          fill="rgba(79, 70, 229, 0.20)"
          stroke="#4f46e5"
          strokeWidth="2"
        />

        {scores.map((score, index) => {
          const point = getPoint(score, index);
          return (
            <circle
              key={labels[index]}
              cx={point.x}
              cy={point.y}
              r="3.5"
              fill="#4338ca"
            />
          );
        })}
      </svg>

      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 9,
          minWidth: 140,
        }}
      >
        {labels.map((label, index) => (
          <div
            key={label}
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              gap: 12,
              fontSize: 12,
            }}
          >
            <span style={{ color: COLORS.muted }}>{label}</span>
            <strong
              style={{
                color: scores[index] > 50 ? COLORS.red : scores[index] > 20 ? COLORS.amber : COLORS.text,
                fontFamily: HEADING_FONT,
              }}
            >
              {scores[index]}/100
            </strong>
          </div>
        ))}
      </div>
    </div>
  );
}

function HighlightedText({ text }) {
  const suspiciousPattern =
    /(within 24 hours|urgent|limited seats|limited slots|registration fee|security deposit|refundable server activation deposit|pay ₹?\s?\d+|₹\s?[\d,]+(?:\.\d+)?(?:\s?to\s?₹?\s?[\d,]+)?|whatsapp only|telegram only|no experience needed|no prior experience|guaranteed|password|otp|click here|verify your account|telegram|gmail\.com|earn ₹?\s?[\d,]+(?:\s?to\s?₹?\s?[\d,]+)?(?:\/month)?|2 hours daily|contact hr manager|activate your id|registration closes|online job portal|job portal|interview scheduled for tomorrow|interview tomorrow|send your cv|share your cv|whatsapp your cv|address will be shared|address will be provided|share cv for address|walk-in tomorrow)/gi;

  const parts = String(text ?? '').split(suspiciousPattern);

  function isSuspicious(part) {
    return new RegExp(suspiciousPattern.source, 'i').test(part);
  }

  function isHighRisk(part) {
    return /urgent|security deposit|refundable|registration fee|pay ₹|otp|password|verify your account|telegram|gmail\.com|activate your id|address will be shared|share cv for address/i.test(
      part
    );
  }

  return (
    <div
      style={{
        padding: '18px 20px',
        background: '#f8fafc',
        border: '1px solid #e2e8f0',
        borderRadius: 12,
        color: '#334155',
        fontSize: 13.5,
        lineHeight: 1.85,
        overflowWrap: 'anywhere',
        whiteSpace: 'pre-wrap',
        fontFamily: FONT,
      }}
    >
      {parts.map((part, index) => {
        if (!isSuspicious(part)) {
          return <span key={index}>{part}</span>;
        }

        const highRisk = isHighRisk(part);

        return (
          <mark
            key={index}
            style={{
              background: highRisk ? '#fee2e2' : '#ffedd5',
              color: highRisk ? '#dc2626' : '#c2410c',
              borderRadius: 4,
              padding: '2px 5px',
              fontWeight: 700,
            }}
          >
            {part}
          </mark>
        );
      })}
    </div>
  );
}

function RiskBadge({ level }) {
  const upLevel = String(level || 'HIGH').toUpperCase();
  if (upLevel === 'UNVERIFIED') {
    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          padding: '4px 10px',
          borderRadius: 20,
          background: '#f1f5f9',
          border: '1px solid #cbd5e1',
          color: '#475569',
          fontSize: 11,
          fontWeight: 800,
          letterSpacing: '0.04em',
          fontFamily: HEADING_FONT,
        }}
      >
        UNVERIFIED
      </span>
    );
  }

  const badgeStyles = {
    CRITICAL: { color: '#dc2626', bg: '#fef2f2', border: '#fecaca' },
    HIGH: { color: '#e11d48', bg: '#fff1f2', border: '#fecdd3' },
    MEDIUM: { color: '#d97706', bg: '#fffbeb', border: '#fde68a' },
    LOW: { color: '#16a34a', bg: '#f0fdf4', border: '#bbf7d0' },
    INFO: { color: '#2563eb', bg: '#eff6ff', border: '#bfdbfe' },
    SUSPICIOUS: { color: '#d97706', bg: '#fffbeb', border: '#fde68a' },
    'HIGH RISK': { color: '#dc2626', bg: '#fef2f2', border: '#fecaca' },
  };

  const style = badgeStyles[upLevel] || badgeStyles.HIGH;

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '4px 10px',
        borderRadius: 20,
        background: style.bg,
        border: `1px solid ${style.border}`,
        color: style.color,
        fontSize: 11,
        fontWeight: 800,
        letterSpacing: '0.04em',
        fontFamily: HEADING_FONT,
      }}
    >
      {upLevel}
    </span>
  );
}

export default function Results() {
  const location = useLocation();
  const navigate = useNavigate();
  let result = location.state?.result;

  if (!result && typeof window !== 'undefined') {
    try {
      const stored = sessionStorage.getItem('scamxray_last_result');
      if (stored) {
        result = JSON.parse(stored);
      }
    } catch {
      // ignore JSON parse error
    }
  }

  if (!result) {
    return (
      <div
        style={{
          minHeight: '80vh',
          display: 'grid',
          placeItems: 'center',
          fontFamily: FONT,
          padding: 24,
        }}
      >
        <div
          style={{
            background: '#ffffff',
            border: `1px solid ${COLORS.border}`,
            borderRadius: 18,
            padding: 36,
            maxWidth: 480,
            width: '100%',
            textAlign: 'center',
            boxShadow: '0 8px 30px rgba(79, 70, 229, 0.06)',
          }}
        >
          <div style={{ fontSize: 42, marginBottom: 14 }}>🛡️</div>
          <h1
            style={{
              fontSize: 24,
              fontFamily: HEADING_FONT,
              fontWeight: 800,
              color: COLORS.text,
              margin: '0 0 10px',
            }}
          >
            No Analysis Results Found
          </h1>
          <p
            style={{
              color: COLORS.muted,
              lineHeight: 1.7,
              fontSize: 14,
              margin: '0 0 24px',
            }}
          >
            Analyze a message, job posting, URL, or screenshot first to view its complete threat intelligence report.
          </p>
          <button
            onClick={() => navigate('/scam-detection')}
            style={primaryButtonStyle}
          >
            Go to Scam Detection
          </button>
        </div>
      </div>
    );
  }

  // 1. Determine Scan Type (URL vs Text vs Screenshot OCR)
  const jobText = String(result.jobText ?? result.text ?? result.scannedText ?? '').trim();
  const urlAnalyzed = String(result.url ?? result.scannedUrl ?? '').trim();
  const rawInputType = String(result.input_type || result.analysisMode || '').toLowerCase();
  const hasUrl = Boolean(urlAnalyzed);
  const isUrlScan = rawInputType.includes('url') || (hasUrl && !jobText);
  const isOcrScan = rawInputType.includes('ocr') || rawInputType.includes('image');
  const inputType = result.input_type || (isUrlScan ? 'URL' : isOcrScan ? 'Screenshot OCR' : 'Text / Message');

  // 2. Core Scores & Unverified State
  // The 'UNVERIFIED' status and 'Domain Not Verified' banner apply ONLY to URL scans whose backend verdict is Unverified.
  const riskScore = normalizeScore(result.risk_score ?? result.score) ?? 0;
  const urlScore = normalizeScore(result.url_score);
  const isUnverifiedVerdict = isUrlScan && result.url_verdict === 'Unverified';
  const hasCautionIndicators = isUrlScan && (
    (Array.isArray(result.indicators) && result.indicators.length > 0) ||
    (urlScore !== null && urlScore > 0)
  );
  const unverifiedNotScored = isUnverifiedVerdict && !hasCautionIndicators;
  const rawRiskLevel = isUnverifiedVerdict ? 'UNVERIFIED' : getRiskLevel(riskScore);
  const riskLevel = rawRiskLevel;
  const riskColor = getRiskColor(riskLevel);

  const ruleScore = normalizeScore(result.rule_score);
  const mlScore = normalizeScore(result.ml_score);
  const llmScore = normalizeScore(result.llm_score);

  // 3. Flags and Indicators
  const flags = isUrlScan && Array.isArray(result.indicators) && result.indicators.length > 0
    ? result.indicators
    : [
        ...(Array.isArray(result.rule_flags) ? result.rule_flags : []),
        ...(Array.isArray(result.url_flags) ? result.url_flags : []),
      ];

  const categories = Array.isArray(result.categories)
    ? result.categories
    : result.categories
      ? [result.categories]
      : [];

  const tips = Array.isArray(result.safety_tips)
    ? result.safety_tips
    : Array.isArray(result.tips)
      ? result.tips
      : [];

  const explanation =
    result.explanation ||
    result.ai_explanation ||
    result.llm_explanation ||
    'Automated analysis completed. Review the detected indicators and verify the source independently.';

  // 4. Scam Category & Classification Criteria
  const scamCategory = result.scam_category || (isUnverifiedVerdict ? 'Unverified URL' : riskScore > 30 ? 'Suspicious Communication' : 'Unclassified');
  const classificationCriteria = Array.isArray(result.classification_criteria) && result.classification_criteria.length > 0
    ? result.classification_criteria
    : flags.length > 0
      ? flags.slice(0, 4).map(getFlagText)
      : ['No explicit high-risk scam patterns matched'];

  // 5. URL Dedicated Verdict & Reason (Applicable only to URL scans)
  const urlVerdict = isUrlScan ? (result.url_verdict || (
    urlScore >= 35
      ? 'Suspicious / Potentially Fraudulent'
      : 'Unverified'
  )) : null;

  const urlVerdictReason = isUrlScan ? (result.url_verdict_reason || (
    urlVerdict === 'Likely Legitimate'
      ? 'The domain passed positive verification checks: valid TLS, established domain age, and active reachability.'
      : urlVerdict === 'Suspicious / Potentially Fraudulent'
        ? 'The URL exhibits high-risk structural characteristics commonly associated with malicious links.'
        : 'No threat indicators detected in URL syntax, but positive verification evidence is incomplete. Domain remains unverified.'
  )) : null;

  const verificationChecksList = Array.isArray(result.verification_checks) ? result.verification_checks : [];

  // 6. Risk Radar Dynamic Axes: omit any axis whose layer is N/A
  const rawRadar = result.radar_indicators || {};
  const radarAxes = [];

  if (!isUrlScan) {
    // For text/OCR scans: include real signals from text rules & ML; omit URL Risk if no URL
    radarAxes.push({
      label: 'Urgency',
      value: normalizeScore(rawRadar.urgency) ?? (ruleScore ? Math.min(100, ruleScore) : 0),
    });
    radarAxes.push({
      label: 'Payment',
      value: normalizeScore(rawRadar.payment) ?? 0,
    });
    if (hasUrl && urlScore !== null) {
      radarAxes.push({
        label: 'URL Risk',
        value: urlScore,
      });
    }
    if (mlScore !== null) {
      radarAxes.push({
        label: 'ML Score',
        value: mlScore,
      });
    }
    radarAxes.push({
      label: 'Impersonation',
      value: normalizeScore(rawRadar.impersonation) ?? 0,
    });
  } else {
    // For URL scans: only include layers backed by real data
    if (urlScore !== null) {
      radarAxes.push({
        label: 'URL Risk',
        value: urlScore,
      });
    }
    if (rawRadar.impersonation && rawRadar.impersonation > 0) {
      radarAxes.push({
        label: 'Brand Spoof',
        value: rawRadar.impersonation,
      });
    }
  }

  const layerScores = [
    ['Rule Engine Heuristics', ruleScore, !isUrlScan],
    ['Machine Learning Classifier', mlScore, !isUrlScan && mlScore !== null],
    ['URL Structural Inspection', urlScore, isUrlScan],
    ['AI Context Assessment', llmScore, !isUrlScan && llmScore !== null],
  ];

  const availableLayers = layerScores.filter(([, score, isAvail]) => isAvail && score !== null);

  // Derive banner properties strictly based on scan type
  let bannerTitle;
  let bannerSubtitle;
  let bannerBg;
  let bannerBorder;
  let bannerBadgeLevel;
  let bannerColor;

  if (isUrlScan) {
    if (urlVerdict === 'Suspicious / Potentially Fraudulent') {
      bannerTitle = 'Suspicious / Potentially Fraudulent';
      const effScore = urlScore ?? riskScore ?? 0;
      if (effScore >= 70) {
        bannerSubtitle = 'Structural deception indicators were detected in the URL syntax. Do not enter credentials, financial information, or personal data.';
        bannerBg = 'linear-gradient(110deg, #fff1f2 0%, #fff7f7 100%)';
        bannerBorder = `1px solid ${COLORS.red}50`;
        bannerBadgeLevel = 'HIGH RISK';
        bannerColor = COLORS.red;
      } else {
        bannerSubtitle = 'Cautionary deception indicators were detected in the URL syntax. Do not enter credentials, financial information, or personal data.';
        bannerBg = 'linear-gradient(110deg, #fffbeb 0%, #fff7ed 100%)';
        bannerBorder = `1px solid ${COLORS.amber}50`;
        bannerBadgeLevel = 'SUSPICIOUS';
        bannerColor = COLORS.amber;
      }
    } else if (urlVerdict === 'Likely Legitimate') {
      bannerTitle = 'Likely Legitimate';
      bannerSubtitle = 'Likely legitimate - basic checks passed; this is not a guarantee of safety.';
      bannerBg = 'linear-gradient(110deg, #f0fdf4 0%, #f7fff9 100%)';
      bannerBorder = `1px solid ${COLORS.green}50`;
      bannerBadgeLevel = 'LOW';
      bannerColor = COLORS.green;
    } else {
      // Unverified
      bannerTitle = 'Domain Not Verified';
      const indicatorCount = Array.isArray(result.indicators) ? result.indicators.length : 0;
      if (indicatorCount > 0 || (urlScore !== null && urlScore > 0)) {
        bannerSubtitle = `${indicatorCount} caution indicator${indicatorCount === 1 ? '' : 's'} found — not verified. Absence of confirmed fraud does not verify safety.`;
      } else {
        bannerSubtitle = 'No threat indicators found — Not verified. Absence of attack patterns does not confirm legitimacy. Verify the organization independently.';
      }
      bannerBg = 'linear-gradient(110deg, #f8fafc 0%, #f1f5f9 100%)';
      bannerBorder = '1px solid #cbd5e1';
      bannerBadgeLevel = 'UNVERIFIED';
      bannerColor = COLORS.slate;
    }
  } else {
    // Text / OCR scan banner
    if (riskLevel === 'HIGH') {
      bannerTitle = 'Critical Fraud Risk Detected';
      bannerSubtitle = 'Severe indicators of fraud, data harvesting, or credential theft: strong indicators of fraud detected. Do not send payments, share CVs, or disclose personal details.';
      bannerBg = 'linear-gradient(110deg, #fff1f2 0%, #fff7f7 100%)';
      bannerBorder = `1px solid ${COLORS.red}50`;
      bannerBadgeLevel = 'HIGH';
      bannerColor = COLORS.red;
    } else if (riskLevel === 'MEDIUM') {
      bannerTitle = 'Suspicious Activity Detected';
      bannerSubtitle = 'Multiple cautionary patterns were found. Carefully cross-check the company, sender address, and communication channels.';
      bannerBg = 'linear-gradient(110deg, #fffbeb 0%, #fff7ed 100%)';
      bannerBorder = `1px solid ${COLORS.amber}50`;
      bannerBadgeLevel = 'MEDIUM';
      bannerColor = COLORS.amber;
    } else {
      bannerTitle = 'Lower threat level - no strong scam indicators found';
      bannerSubtitle = 'Few standard threat patterns were matched. Note that targeted or novel scams may still present minimal rule signatures.';
      bannerBg = 'linear-gradient(110deg, #f0fdf4 0%, #f7fff9 100%)';
      bannerBorder = `1px solid ${COLORS.green}50`;
      bannerBadgeLevel = 'LOW';
      bannerColor = COLORS.green;
    }
  }

  return (
    <div
      style={{
        maxWidth: 1140,
        margin: '0 auto',
        padding: '10px 0 48px',
        fontFamily: FONT,
        color: COLORS.text,
        display: 'flex',
        flexDirection: 'column',
        gap: 22,
      }}
    >
      {/* Top action bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        <button
          onClick={() => navigate('/scam-detection')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            border: 0,
            padding: '6px 0',
            background: 'transparent',
            color: COLORS.primary,
            fontSize: 13,
            fontWeight: 700,
            cursor: 'pointer',
            fontFamily: FONT,
          }}
        >
          ← Analyze Another Threat
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span
            style={{
              fontSize: 11,
              fontWeight: 700,
              color: COLORS.muted,
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
            }}
          >
            Threat Intelligence Report
          </span>
          <span style={{ color: '#cbd5e1' }}>•</span>
          <span
            style={{
              fontSize: 11,
              fontWeight: 600,
              background: '#f1f5f9',
              padding: '3px 8px',
              borderRadius: 6,
              color: '#475569',
            }}
          >
            {inputType} Scan
          </span>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          1. OVERALL RISK ASSESSMENT
      ───────────────────────────────────────────────────────────── */}
      <section
        style={{
          background: bannerBg,
          border: bannerBorder,
          borderRadius: 18,
          padding: '28px clamp(20px, 3.5vw, 36px)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 24,
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.03)',
        }}
      >
        <div style={{ flex: '1 1 360px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <span
              style={{
                fontSize: 11,
                fontWeight: 800,
                letterSpacing: '0.08em',
                color: bannerColor,
                textTransform: 'uppercase',
              }}
            >
              Overall Risk Assessment
            </span>
            <RiskBadge level={bannerBadgeLevel} />
          </div>

          <h1
            style={{
              color: COLORS.text,
              fontSize: 'clamp(24px, 3vw, 34px)',
              fontWeight: 850,
              fontFamily: HEADING_FONT,
              margin: '0 0 10px',
              letterSpacing: '-0.025em',
              lineHeight: 1.2,
            }}
          >
            {bannerTitle}
          </h1>

          <p
            style={{
              color: '#475569',
              fontSize: 14,
              lineHeight: 1.7,
              maxWidth: 560,
              margin: '0 0 16px',
            }}
          >
            {bannerSubtitle}
          </p>

          {/* Prominent Scam Category Badge */}
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 8,
              background: '#ffffff',
              border: `1px solid ${bannerColor}40`,
              borderRadius: 10,
              padding: '8px 14px',
              boxShadow: '0 2px 8px rgba(0,0,0,0.03)',
            }}
          >
            <span style={{ fontSize: 11, fontWeight: 700, color: COLORS.muted, textTransform: 'uppercase' }}>
              Identified Threat Category:
            </span>
            <strong
              style={{
                fontSize: 13,
                fontWeight: 800,
                color: bannerColor,
                fontFamily: HEADING_FONT,
              }}
            >
              {scamCategory}
            </strong>
          </div>
        </div>

        {/* Mathematical Circular Progress Score Gauge */}
        <CircularScoreGauge
          score={unverifiedNotScored ? null : riskScore}
          displayText={unverifiedNotScored ? 'Not scored' : null}
          color={bannerColor}
          size={140}
          strokeWidth={10}
          label={unverifiedNotScored ? 'UNVERIFIED' : 'OUT OF 100'}
        />
      </section>

      {/* Dedicated URL Verdict Banner (if URL analyzed) */}
      {isUrlScan && hasUrl && (
        <div
          style={{
            padding: '18px 22px',
            background:
              urlVerdict === 'Likely Legitimate'
                ? COLORS.greenBg
                : urlVerdict === 'Suspicious / Potentially Fraudulent'
                  ? COLORS.redBg
                  : COLORS.slateBg,
            border: `1px solid ${
              urlVerdict === 'Likely Legitimate'
                ? COLORS.greenBorder
                : urlVerdict === 'Suspicious / Potentially Fraudulent'
                  ? COLORS.redBorder
                  : COLORS.slateBorder
            }`,
            borderRadius: 14,
            display: 'flex',
            flexDirection: 'column',
            gap: 8,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
            <span
              style={{
                fontSize: 11,
                fontWeight: 800,
                textTransform: 'uppercase',
                letterSpacing: '0.06em',
                color:
                  urlVerdict === 'Likely Legitimate'
                    ? COLORS.green
                    : urlVerdict === 'Suspicious / Potentially Fraudulent'
                      ? COLORS.red
                      : COLORS.slate,
              }}
            >
              Is this URL legitimate, suspicious, or unverified?
            </span>
            <span
              style={{
                padding: '4px 12px',
                borderRadius: 20,
                fontWeight: 800,
                fontSize: 12,
                fontFamily: HEADING_FONT,
                background: '#ffffff',
                color:
                  urlVerdict === 'Likely Legitimate'
                    ? COLORS.green
                    : urlVerdict === 'Suspicious / Potentially Fraudulent'
                      ? COLORS.red
                      : COLORS.slate,
                border: `1px solid ${
                  urlVerdict === 'Likely Legitimate'
                    ? COLORS.greenBorder
                    : urlVerdict === 'Suspicious / Potentially Fraudulent'
                      ? COLORS.redBorder
                      : COLORS.slateBorder
                }`,
              }}
            >
              Verdict: {urlVerdict}
            </span>
          </div>

          <p
            style={{
              fontSize: 14,
              fontWeight: 600,
              color: COLORS.text,
              lineHeight: 1.6,
              margin: 0,
            }}
          >
            {urlVerdictReason}
          </p>

          <p
            style={{
              fontSize: 11.5,
              color: COLORS.muted,
              margin: '4px 0 0',
              lineHeight: 1.5,
            }}
          >
            ℹ️ <strong>Evidence & Verification Scope:</strong> Threat risk is computed strictly from structural indicators. Verification status evaluates DNS resolution, TLS certificates, RDAP domain age, and safe HTTP reachability with SSRF protections.
          </p>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          2. MULTI-VECTOR SCORE BREAKDOWN
      ───────────────────────────────────────────────────────────── */}
      <Panel title="📊 Multi-Vector Score Breakdown">
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: 12,
          }}
        >
          <ScoreCard
            title="Overall Risk"
            score={unverifiedNotScored ? null : riskScore}
            displayText={unverifiedNotScored ? 'Not scored' : null}
            subtitle={isUnverifiedVerdict ? 'Domain not verified' : !isUrlScan ? 'Weighted from available layers' : 'Final composite score'}
            isAvailable={true}
          />
          <ScoreCard
            title="Rule Engine"
            score={ruleScore}
            subtitle={isUrlScan ? 'N/A — URL scan only' : 'Pattern heuristics'}
            isAvailable={!isUrlScan}
          />
          <ScoreCard
            title="ML Model"
            score={mlScore}
            subtitle={isUrlScan ? 'N/A — no text analysed' : mlScore !== null ? 'Statistical classifier' : 'Not evaluated'}
            isAvailable={!isUrlScan && mlScore !== null}
          />
          <ScoreCard
            title="URL Inspection"
            score={urlScore}
            subtitle={hasUrl ? 'Threat indicators score' : 'No URL submitted'}
            isAvailable={hasUrl}
          />
          <ScoreCard
            title="AI Analysis"
            score={llmScore}
            subtitle={isUrlScan ? 'N/A — no page content analysed' : llmScore !== null ? 'Contextual reasoning' : 'Analysis unavailable'}
            isAvailable={!isUrlScan && llmScore !== null}
          />
        </div>
      </Panel>

      {/* ─────────────────────────────────────────────────────────────
          3. CLASSIFICATION CRITERIA, THREAT EVIDENCE & VERIFICATION STATUS
      ───────────────────────────────────────────────────────────── */}
      <Panel title="🎯 Classification Criteria & Threat Evidence">
        <p style={{ color: COLORS.muted, fontSize: 13, margin: '0 0 14px' }}>
          Specific criteria and detection signals that classified this content as <strong>{scamCategory}</strong>:
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {classificationCriteria.map((criterion, idx) => (
            <div
              key={idx}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 10,
                padding: '10px 14px',
                borderRadius: 10,
                background: '#f8fafc',
                border: '1px solid #e2e8f0',
                fontSize: 13,
                color: '#334155',
                lineHeight: 1.5,
              }}
            >
              <span style={{ color: isUnverifiedVerdict ? COLORS.slate : riskColor, fontWeight: 800 }}>•</span>
              <span style={{ flex: 1 }}>{criterion}</span>
            </div>
          ))}
        </div>

        {/* Separate Labeled Block: Verification Status (Checks Performed / Failed / Not Performed) */}
        {isUrlScan && hasUrl && verificationChecksList.length > 0 && (
          <div style={{ marginTop: 18, paddingTop: 16, borderTop: '1px solid #e2e8f0' }}>
            <h3 style={{ fontSize: 13.5, fontWeight: 800, fontFamily: HEADING_FONT, margin: '0 0 10px', color: COLORS.text }}>
              🛡️ URL Verification Status (Independent Security Checks)
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 10 }}>
              {verificationChecksList.map((check, i) => {
                const isPerf = check.status === 'performed';
                const isFail = check.status === 'failed';
                const statusColor = isPerf ? COLORS.green : isFail ? COLORS.amber : COLORS.slate;
                const statusBg = isPerf ? COLORS.greenBg : isFail ? COLORS.amberBg : '#f1f5f9';
                const statusBorder = isPerf ? COLORS.greenBorder : isFail ? COLORS.amberBorder : '#cbd5e1';

                return (
                  <div
                    key={i}
                    style={{
                      padding: '12px 14px',
                      borderRadius: 10,
                      background: '#ffffff',
                      border: `1px solid ${COLORS.border}`,
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'space-between',
                      gap: 6,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                      <strong style={{ fontSize: 12, color: COLORS.text, fontFamily: HEADING_FONT }}>
                        {check.name}
                      </strong>
                      <span
                        style={{
                          fontSize: 10,
                          fontWeight: 800,
                          padding: '2px 7px',
                          borderRadius: 8,
                          background: statusBg,
                          color: statusColor,
                          border: `1px solid ${statusBorder}`,
                          textTransform: 'uppercase',
                        }}
                      >
                        {check.status.replace('_', ' ')}
                      </span>
                    </div>
                    <p style={{ margin: 0, fontSize: 11.5, color: COLORS.muted, lineHeight: 1.5 }}>
                      {check.details}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {categories.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 8, marginTop: 14, paddingTop: 12, borderTop: '1px dashed #e2e8f0' }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: COLORS.muted }}>Rule Categories Triggered:</span>
            {categories.map((cat, idx) => (
              <span
                key={idx}
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  background: COLORS.primaryLight,
                  color: COLORS.primaryDark,
                  padding: '3px 10px',
                  borderRadius: 14,
                }}
              >
                #{formatLabel(cat)}
              </span>
            ))}
          </div>
        )}
      </Panel>

      {/* ─────────────────────────────────────────────────────────────
          4. LAYER SCORES COMPARISON (Hidden if < 2 layers with real values; rows that are N/A are omitted)
      ───────────────────────────────────────────────────────────── */}
      {availableLayers.length >= 2 && (
        <Panel title="📈 Layer Scores Comparison">
          <p style={{ color: COLORS.muted, fontSize: 12, margin: '0 0 18px' }}>
            Comparison of confidence scores across independent security layers:
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {availableLayers.map(([label, score]) => {
              const safeScore = normalizeScore(score);
              const color = getRiskColor(getRiskLevel(safeScore));

              return (
                <div key={label}>
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      fontSize: 12,
                      marginBottom: 6,
                    }}
                  >
                    <span style={{ color: COLORS.text, fontWeight: 600 }}>{label}</span>
                    <strong
                      style={{
                        color: COLORS.text,
                        fontFamily: HEADING_FONT,
                      }}
                    >
                      {`${safeScore}/100`}
                    </strong>
                  </div>

                  <div
                    style={{
                      height: 8,
                      background: '#f1f5f9',
                      borderRadius: 12,
                      overflow: 'hidden',
                    }}
                  >
                    <div
                      style={{
                        width: `${safeScore}%`,
                        height: '100%',
                        borderRadius: 12,
                        background: color,
                        transition: 'width 0.4s ease',
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      {/* ─────────────────────────────────────────────────────────────
          5. RISK RADAR INDICATORS
      ───────────────────────────────────────────────────────────── */}
      {radarAxes.length >= 3 && (
        <Panel title="🕸️ Risk Radar Indicators">
          <p style={{ color: COLORS.muted, fontSize: 12, margin: '0 0 16px' }}>
            Multi-dimensional threat footprint derived from real backend signals:
          </p>
          <RiskRadar axes={radarAxes} />
        </Panel>
      )}

      {/* ─────────────────────────────────────────────────────────────
          6. DETECTED FLAGS & RED FLAGS
      ───────────────────────────────────────────────────────────── */}
      <Panel
        title={`🚨 Detected Flags & Red Flags (${flags.length})`}
        badge={
          <span
            style={{
              fontSize: 11,
              fontWeight: 700,
              color: flags.length > 0 ? COLORS.red : isUnverifiedVerdict ? COLORS.slate : COLORS.green,
            }}
          >
            {flags.length > 0
              ? `${flags.length} warning indicator${flags.length === 1 ? '' : 's'}`
              : isUrlScan
                ? 'No threat indicators detected'
                : 'Clean scan'}
          </span>
        }
      >
        {flags.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {flags.map((flag, index) => {
              const rawSeverity = typeof flag === 'object' ? String(flag.severity || 'HIGH').toUpperCase() : 'HIGH';
              const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNVERIFIED'];
              const severity = validSeverities.includes(rawSeverity) ? rawSeverity : 'HIGH';
              const details = typeof flag === 'object' ? flag.explanation || flag.details || flag.reason || '' : '';
              const cardBg = severity === 'CRITICAL' || severity === 'HIGH' ? '#fff7f7' : severity === 'MEDIUM' ? '#fffdf7' : '#f8fafc';
              const cardBorder = severity === 'CRITICAL' || severity === 'HIGH' ? '1px solid #fecaca' : severity === 'MEDIUM' ? '1px solid #fde68a' : '1px solid #e2e8f0';

              return (
                <details
                  key={index}
                  style={{
                    background: cardBg,
                    border: cardBorder,
                    borderRadius: 12,
                    padding: '12px 16px',
                  }}
                >
                  <summary
                    style={{
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      flexWrap: 'wrap',
                      gap: 10,
                      color: '#1e293b',
                      fontSize: 13,
                      fontWeight: 650,
                      lineHeight: 1.5,
                      listStylePosition: 'inside',
                    }}
                  >
                    <span style={{ flex: '1 1 200px' }}>{getFlagText(flag)}</span>
                    <RiskBadge level={severity} />
                  </summary>

                  {details && (
                    <p
                      style={{
                        color: COLORS.muted,
                        fontSize: 12,
                        lineHeight: 1.7,
                        margin: '10px 0 0',
                        paddingTop: 8,
                        borderTop: '1px dashed #fed7d7',
                      }}
                    >
                      {details}
                    </p>
                  )}
                </details>
              );
            })}
          </div>
        ) : (
          <p style={{ color: COLORS.muted, fontSize: 13, margin: 0, lineHeight: 1.7 }}>
            {isUrlScan
              ? isUnverifiedVerdict
                ? 'No structural attack patterns detected. However, positive legitimacy is unverified.'
                : 'No structural attack patterns detected in this URL.'
              : 'No specific rule or link flags were triggered. Always confirm the identity of unknown senders.'}
          </p>
        )}
      </Panel>

      {/* ─────────────────────────────────────────────────────────────
          7. AI THREAT ASSESSMENT & CONTEXT
      ───────────────────────────────────────────────────────────── */}
      <Panel title="✨ AI Threat Assessment & Context">
        <div
          style={{
            padding: '18px 20px',
            borderRadius: 12,
            background: '#f8fafc',
            border: '1px solid #e2e8f0',
            color: '#334155',
            fontSize: 13.5,
            lineHeight: 1.85,
            overflowWrap: 'anywhere',
          }}
        >
          {explanation}
        </div>
      </Panel>

      {/* ─────────────────────────────────────────────────────────────
          8. ACTIONABLE SAFETY RECOMMENDATIONS
      ───────────────────────────────────────────────────────────── */}
      <Panel title="🛡️ Actionable Safety Recommendations">
        {tips.length > 0 ? (
          <ul style={{ paddingLeft: 22, margin: 0, color: '#334155' }}>
            {tips.map((tip, index) => (
              <li key={index} style={{ fontSize: 13.5, lineHeight: 1.9, marginBottom: 4 }}>
                {getTipText(tip)}
              </li>
            ))}
          </ul>
        ) : isUrlScan ? (
          <ul style={{ paddingLeft: 22, margin: 0, color: '#334155' }}>
            {isUnverifiedVerdict ? (
              <>
                <li style={{ fontSize: 13.5, lineHeight: 1.9 }}>
                  This domain is an unverified external address or reserved namespace; verify its authenticity through independent registries before proceeding.
                </li>
                <li style={{ fontSize: 13.5, lineHeight: 1.9 }}>
                  Never submit passwords, personal credentials, or payment details on unverified web destinations.
                </li>
              </>
            ) : urlVerdict === 'Likely Legitimate' ? (
              <>
                <li style={{ fontSize: 13.5, lineHeight: 1.9 }}>
                  Confirm the browser address bar matches the exact intended domain without typos.
                </li>
                <li style={{ fontSize: 13.5, lineHeight: 1.9 }}>
                  Ensure the connection uses valid HTTPS encryption before submitting any sensitive information.
                </li>
              </>
            ) : (
              <>
                <li style={{ fontSize: 13.5, lineHeight: 1.9 }}>
                  Do not enter passwords, credit cards, or personal credentials on this link.
                </li>
                <li style={{ fontSize: 13.5, lineHeight: 1.9 }}>
                  Be cautious of links using misleading subdomains or URL shorteners to hide their actual destination.
                </li>
              </>
            )}
          </ul>
        ) : (
          <ul style={{ paddingLeft: 22, margin: 0, color: '#334155' }}>
            <li style={{ fontSize: 13.5, lineHeight: 1.9 }}>
              Never send resumes or identity proofs to unverified personal WhatsApp numbers without confirming corporate credentials.
            </li>
            <li style={{ fontSize: 13.5, lineHeight: 1.9 }}>
              Never pay registration fees, application deposits, or kit charges to secure employment.
            </li>
            <li style={{ fontSize: 13.5, lineHeight: 1.9 }}>
              Verify job postings exclusively on the organization&apos;s verified careers portal.
            </li>
            <li style={{ fontSize: 13.5, lineHeight: 1.9 }}>
              Do not attend interviews at undisclosed locations that withhold addresses until personal information is submitted.
            </li>
          </ul>
        )}
      </Panel>

      {/* ─────────────────────────────────────────────────────────────
          9. ORIGINAL CONTENT — RISK PHRASE HIGHLIGHTS
      ───────────────────────────────────────────────────────────── */}
      {jobText.trim() ? (
        <Panel title="🔎 Original Content — Risk Phrase Highlights">
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: 8,
              marginBottom: 14,
            }}
          >
            <span
              style={{
                color: '#dc2626',
                background: '#fff1f2',
                border: '1px solid #fecdd3',
                borderRadius: 20,
                padding: '4px 10px',
                fontSize: 11,
                fontWeight: 700,
              }}
            >
              🔴 High Risk Phrase
            </span>
            <span
              style={{
                color: '#b45309',
                background: '#fffbeb',
                border: '1px solid #fed7aa',
                borderRadius: 20,
                padding: '4px 10px',
                fontSize: 11,
                fontWeight: 700,
              }}
            >
              🟠 Cautionary Cue
            </span>
          </div>

          <HighlightedText text={jobText} />
        </Panel>
      ) : urlAnalyzed ? (
        <Panel title="🔎 Analyzed URL Target">
          <div
            style={{
              padding: '14px 18px',
              borderRadius: 10,
              background: '#f8fafc',
              border: '1px solid #e2e8f0',
              fontFamily: 'monospace',
              fontSize: 13,
              color: '#334155',
              wordBreak: 'break-all',
            }}
          >
            {urlAnalyzed}
          </div>
        </Panel>
      ) : null}

      {/* ─────────────────────────────────────────────────────────────
          10. ACTION BUTTONS & SECURITY DISCLAIMER
      ───────────────────────────────────────────────────────────── */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'flex-end',
          flexWrap: 'wrap',
          gap: 12,
          margin: '10px 0',
        }}
      >
        <button
          onClick={() => navigate('/scam-detection')}
          style={secondaryButtonStyle}
        >
          ← Analyze Another Threat
        </button>

        <button
          onClick={() => navigate('/dashboard')}
          style={primaryButtonStyle}
        >
          Back to Dashboard
        </button>
      </div>

      <div
        style={{
          background: '#fffbeb',
          border: '1px solid #fed7aa',
          borderRadius: 12,
          padding: '14px 18px',
          color: '#92400e',
          fontSize: 12,
          lineHeight: 1.7,
        }}
      >
        <strong>⚠️ Security Disclaimer:</strong> ScamXRay provides automated threat analysis combining heuristics, statistical classification, and URL structural inspection. No algorithmic evaluation can provide 100% certainty. Always verify communication independently through official, verified channels before taking financial or personal actions.
      </div>
    </div>
  );
}

const primaryButtonStyle = {
  border: 0,
  borderRadius: 10,
  padding: '11px 22px',
  background: 'linear-gradient(135deg, #4f46e5 0%, #4338ca 100%)',
  color: '#ffffff',
  fontFamily: FONT,
  fontSize: 13,
  fontWeight: 750,
  cursor: 'pointer',
  boxShadow: '0 4px 14px rgba(79, 70, 229, 0.20)',
};

const secondaryButtonStyle = {
  border: '1px solid #cbd5e1',
  borderRadius: 10,
  padding: '11px 22px',
  background: '#ffffff',
  color: COLORS.primary,
  fontFamily: FONT,
  fontSize: 13,
  fontWeight: 750,
  cursor: 'pointer',
};
