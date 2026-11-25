import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useOCR } from '../hooks/useOCR';
import {
  MessageSquareIcon,
  GlobeIcon,
  ImageIcon,
  ArrowRightIcon,
  AlertTriangleIcon,
  CheckCircleIcon,
  RefreshCwIcon,
  ShieldIcon
} from '../components/Icons';

const API_URL = 'http://127.0.0.1:5000/analyze';

const TEST_DATASETS = [
  { label: 'Select a sample to test...', value: '' },
  {
    label: '🚨 WhatsApp Smishing (Registration Fee + Telegram)',
    value: 'Urgent opening: WFH Data Entry Associate. Earn ₹45,000/month. No experience needed. Pay ₹500 refundable registration fee to activate server account. WhatsApp only: +91 98765 43210. Limited slots, apply within 24 hours!',
  },
  {
    label: '🚨 Telegram Crypto Task Scam',
    value: 'Part-time opportunity: Simple YouTube video likes and rating tasks. Earn ₹3,000 to ₹5,000 per day payout same day. Contact manager on Telegram @cryptotasks_hr. No degree required. Deposit ₹1,000 to unlock VIP tasks.',
  },
  {
    label: '🚨 Banking KYC Phishing Lure',
    value: 'Dear Customer, your HDFC net banking account is blocked due to incomplete KYC. Verify your bank account immediately by clicking the link or your account will be suspended within 24 hours. Contact customer support.',
  },
  {
    label: '✅ Legit: Tech Recruitment Offer',
    value: 'Tata Consultancy Services is hiring Software Engineers with 3+ years experience in Java, Spring Boot, and PostgreSQL. Apply directly at our official careers portal https://careers.tcs.com. No registration fees are ever charged at any stage.',
  },
];

function normalizeFlags(flags) {
  if (!Array.isArray(flags)) return [];
  return flags.map((flag) => {
    if (typeof flag === 'string') {
      return { text: flag, severity: 'HIGH' };
    }
    return {
      text: flag.text || flag.message || flag.description || flag.name || 'Potential risk indicator',
      severity: String(flag.severity || 'HIGH').toUpperCase(),
    };
  });
}

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

function getRiskTheme(level) {
  switch (level) {
    case 'LOW':
      return {
        label: 'Low Risk',
        color: '#10b981',
        bg: '#ecfdf5',
        border: '#a7f3d0',
        badgeBg: 'rgba(16, 185, 129, 0.12)',
        description: 'Few or no common scam indicators detected. Practice standard digital caution.',
      };
    case 'MEDIUM':
      return {
        label: 'Medium Risk',
        color: '#d97706',
        bg: '#fffbeb',
        border: '#fde68a',
        badgeBg: 'rgba(217, 119, 6, 0.12)',
        description: 'Suspicious indicators detected. Independently verify the sender before taking action.',
      };
    case 'HIGH':
    default:
      return {
        label: 'High Risk Detected',
        color: '#ef4444',
        bg: '#fef2f2',
        border: '#fecaca',
        badgeBg: 'rgba(239, 68, 68, 0.12)',
        description: 'Strong fraud indicators detected. Do not share funds, OTPs, or sensitive credentials.',
      };
  }
}

export default function Analyzer() {
  const navigate = useNavigate();
  const fileRef = useRef(null);
  const previewUrlRef = useRef(null);

  // Active analysis mode tab: 'text' | 'url' | 'image'
  const [activeTab, setActiveTab] = useState('text');

  // Input states
  const [textInput, setTextInput] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [selectedImage, setSelectedImage] = useState(null);
  const [dragOver, setDragOver] = useState(false);

  // OCR state hook
  const { extractText, progress: ocrProgress, isLoading: ocrLoading, error: ocrHookError } = useOCR();
  const [ocrExtractedText, setOcrExtractedText] = useState('');

  // Analysis status
  const [analyzing, setAnalyzing] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);

  // Revoke object URLs on unmount
  useEffect(() => {
    return () => {
      if (previewUrlRef.current) {
        URL.revokeObjectURL(previewUrlRef.current);
      }
    };
  }, []);

  // Handle Tab Switch
  const handleTabSwitch = (tab) => {
    setActiveTab(tab);
    setErrorMessage('');
  };

  // Preset Dataset Handler
  const handleDatasetSelect = (e) => {
    const val = e.target.value;
    if (val) {
      setTextInput(val);
      setErrorMessage('');
    }
  };

  // Image Upload Handler
  const handleImageFile = async (file) => {
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      setErrorMessage('Please upload a valid image file (PNG, JPG, JPEG, or WEBP).');
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      setErrorMessage('File size exceeds 10MB limit. Please upload a smaller screenshot.');
      return;
    }

    if (previewUrlRef.current) {
      URL.revokeObjectURL(previewUrlRef.current);
    }

    const imageUrl = URL.createObjectURL(file);
    previewUrlRef.current = imageUrl;
    setSelectedImage(imageUrl);
    setOcrExtractedText('');
    setErrorMessage('');

    try {
      const extracted = await extractText(file);
      const clean = String(extracted || '').trim();
      setOcrExtractedText(clean);

      if (!clean) {
        setErrorMessage('No readable text found in this image. Try a clearer screenshot or paste the text manually.');
      }
    } catch {
      setErrorMessage('Could not extract text from this screenshot. Please try another image or paste manually.');
    }
  };

  // Core Analysis Submission (Preserves /analyze backend workflow exactly)
  const executeAnalysis = async (contentPayload) => {
    const { text = '', url = '' } = contentPayload;
    const cleanText = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
    const cleanUrl = url.trim();

    if (!cleanText && !cleanUrl) {
      setErrorMessage('Please provide message text or a URL to analyze.');
      return;
    }

    setAnalyzing(true);
    setErrorMessage('');

    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: cleanText,
          url: cleanUrl,
          input_type: activeTab === 'image' ? 'ocr' : activeTab,
        }),
      });

      let data;
      try {
        data = await response.json();
      } catch {
        throw new Error('Backend returned an unparseable response.');
      }

      if (!response.ok) {
        throw new Error(data?.error || data?.message || `Analysis failed with HTTP status ${response.status}.`);
      }

      const ruleScore = normalizeScore(data.rule_score);
      const mlScore = normalizeScore(data.ml_score);
      const urlScore = normalizeScore(data.url_score);
      const riskScore = normalizeScore(data.risk_score) ?? Math.max(ruleScore ?? 0, mlScore ?? 0, urlScore ?? 0);
      const riskLevel = getRiskLevel(riskScore);

      const parsedResult = {
        ...data,
        risk_score: riskScore,
        risk_level: riskLevel,
        rule_score: ruleScore,
        ml_score: mlScore,
        url_score: urlScore,
        rule_flags: normalizeFlags(data.rule_flags),
        url_flags: normalizeFlags(data.url_flags),
        categories: Array.isArray(data.categories) ? data.categories : [],
        explanation: data.explanation || 'Automated analysis completed. Review the detected indicators below.',
        safety_tips: Array.isArray(data.safety_tips) ? data.safety_tips : [],
        scannedText: cleanText,
        scannedUrl: cleanUrl,
        analysisMode: activeTab,
      };

      setAnalysisResult(parsedResult);

      const finalResult = {
        ...parsedResult,
        input_type: activeTab === 'text' ? 'Text / Message' : activeTab === 'url' ? 'URL' : 'Screenshot OCR',
        jobText: data.jobText || data.text || cleanText,
        url: cleanUrl,
      };

      try {
        sessionStorage.setItem('scamxray_last_result', JSON.stringify(finalResult));
      } catch {
        // ignore storage errors
      }

      navigate('/results', {
        state: {
          result: finalResult,
        },
      });
    } catch (err) {
      setErrorMessage(err.message || 'Could not connect to the backend server at http://127.0.0.1:5000.');
    } finally {
      setAnalyzing(false);
    }
  };

  // Handlers for specific tab submissions
  const handleAnalyzeText = () => executeAnalysis({ text: textInput, url: '' });
  const handleAnalyzeUrl = () => executeAnalysis({ text: '', url: urlInput });
  const handleAnalyzeImage = () => executeAnalysis({ text: ocrExtractedText, url: '' });

  // Reset scan to start another investigation
  const handleResetScan = () => {
    setAnalysisResult(null);
    setErrorMessage('');
  };

  return (
    <div style={{ maxWidth: 1080, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* ─────────────────────────────────────────────────────────────
          1. PAGE HEADER
      ───────────────────────────────────────────────────────────── */}
      <div>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: '#6366f1', fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 6 }}>
          <ShieldIcon size={13} color="#6366f1" />
          <span>Core Detection Engine</span>
        </div>
        <h1
          style={{
            fontFamily: 'var(--font-heading)',
            fontSize: 'clamp(22px, 2.5vw, 28px)',
            fontWeight: 800,
            color: '#0f172a',
            letterSpacing: '-0.025em',
            margin: '0 0 6px',
            lineHeight: 1.25,
          }}
        >
          Scam Detection
        </h1>
        <p
          style={{
            fontSize: 14.5,
            color: '#64748b',
            margin: 0,
            maxWidth: 680,
            lineHeight: 1.6,
          }}
        >
          Analyse suspicious messages, URLs and screenshots to identify potential digital threats.
        </p>
      </div>

      {/* ─────────────────────────────────────────────────────────────
          2. UNIFIED RESULTS VIEW (If a scan is completed)
      ───────────────────────────────────────────────────────────── */}
      {analysisResult ? (
        <div className="card fade-up" style={{ padding: '32px 36px', background: '#ffffff', border: '1px solid rgba(99, 102, 241, 0.16)' }}>
          {(() => {
            const theme = getRiskTheme(analysisResult.risk_level);
            return (
              <>
                {/* Result Header Banner */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: 16,
                    paddingBottom: 24,
                    borderBottom: '1px solid rgba(99, 102, 241, 0.12)',
                    marginBottom: 26,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                    <div
                      style={{
                        width: 52,
                        height: 52,
                        borderRadius: 12,
                        background: theme.bg,
                        border: `1.5px solid ${theme.border}`,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: theme.color,
                        fontWeight: 900,
                        fontSize: 20,
                      }}
                    >
                      {analysisResult.risk_level === 'LOW' ? (
                        <CheckCircleIcon size={24} color={theme.color} />
                      ) : (
                        <AlertTriangleIcon size={24} color={theme.color} />
                      )}
                    </div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                        <span style={{ fontSize: 18, fontWeight: 800, color: theme.color, fontFamily: 'var(--font-heading)' }}>
                          {theme.label}
                        </span>
                        <span
                          style={{
                            fontSize: 11,
                            fontWeight: 700,
                            padding: '2px 8px',
                            borderRadius: 12,
                            background: theme.badgeBg,
                            color: theme.color,
                            letterSpacing: '0.04em',
                          }}
                        >
                          {analysisResult.risk_score} / 100
                        </span>
                      </div>
                      <p style={{ fontSize: 13, color: '#64748b', margin: 0, lineHeight: 1.5 }}>
                        {theme.description}
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={handleResetScan}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 7,
                      background: '#f8f7ff',
                      border: '1px solid rgba(99, 102, 241, 0.2)',
                      borderRadius: 30,
                      padding: '9px 18px',
                      fontSize: 13,
                      fontWeight: 600,
                      color: '#475569',
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                      transition: 'all 0.2s',
                    }}
                  >
                    <RefreshCwIcon size={13} color="#475569" />
                    <span>Start Another Scan</span>
                  </button>
                </div>

                {/* Score Breakdown Metrics Grid */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 180px), 1fr))',
                    gap: 14,
                    marginBottom: 26,
                  }}
                >
                  <div style={{ padding: '14px 16px', background: '#faf9ff', borderRadius: 10, border: '1px solid rgba(99, 102, 241, 0.1)' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', marginBottom: 4 }}>
                      Rule Heuristics
                    </div>
                    <div style={{ fontSize: 20, fontWeight: 800, color: '#0f172a' }}>
                      {analysisResult.rule_score ?? '—'} <span style={{ fontSize: 11, color: '#94a3b8' }}>/ 100</span>
                    </div>
                  </div>

                  <div style={{ padding: '14px 16px', background: '#faf9ff', borderRadius: 10, border: '1px solid rgba(99, 102, 241, 0.1)' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', marginBottom: 4 }}>
                      ML Model Probability
                    </div>
                    <div style={{ fontSize: 20, fontWeight: 800, color: '#0f172a' }}>
                      {analysisResult.ml_score ?? '—'} <span style={{ fontSize: 11, color: '#94a3b8' }}>/ 100</span>
                    </div>
                  </div>

                  {analysisResult.url_score !== null && analysisResult.url_score > 0 && (
                    <div style={{ padding: '14px 16px', background: '#faf9ff', borderRadius: 10, border: '1px solid rgba(99, 102, 241, 0.1)' }}>
                      <div style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', marginBottom: 4 }}>
                        URL Structural Risk
                      </div>
                      <div style={{ fontSize: 20, fontWeight: 800, color: '#0f172a' }}>
                        {analysisResult.url_score} <span style={{ fontSize: 11, color: '#94a3b8' }}>/ 100</span>
                      </div>
                    </div>
                  )}

                  <div style={{ padding: '14px 16px', background: '#faf9ff', borderRadius: 10, border: '1px solid rgba(99, 102, 241, 0.1)' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', marginBottom: 4 }}>
                      Scan Mode
                    </div>
                    <div style={{ fontSize: 15, fontWeight: 700, color: '#6366f1', textTransform: 'capitalize', marginTop: 3 }}>
                      {analysisResult.analysisMode} Analysis
                    </div>
                  </div>
                </div>

                {/* Explanation Section */}
                <div style={{ marginBottom: 24 }}>
                  <h3 style={{ fontSize: 14.5, fontWeight: 700, color: '#0f172a', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 7 }}>
                    <span>Analysis Summary</span>
                  </h3>
                  <div
                    style={{
                      padding: 16,
                      background: '#f8f7ff',
                      borderRadius: 10,
                      border: '1px solid rgba(99, 102, 241, 0.14)',
                      fontSize: 13.5,
                      lineHeight: 1.7,
                      color: '#334155',
                    }}
                  >
                    {analysisResult.explanation}
                  </div>
                </div>

                {/* Detected Red Flags & Indicators */}
                {(analysisResult.rule_flags?.length > 0 || analysisResult.url_flags?.length > 0) && (
                  <div style={{ marginBottom: 24 }}>
                    <h3 style={{ fontSize: 14.5, fontWeight: 700, color: '#0f172a', marginBottom: 10 }}>
                      Detected Indicators ({analysisResult.rule_flags.length + analysisResult.url_flags.length})
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {[...analysisResult.rule_flags, ...analysisResult.url_flags].map((flag, idx) => (
                        <div
                          key={idx}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '10px 14px',
                            borderRadius: 8,
                            background: '#fff7f7',
                            border: '1px solid #fee2e2',
                            fontSize: 13,
                            color: '#991b1b',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <AlertTriangleIcon size={15} color="#ef4444" />
                            <span>{flag.text}</span>
                          </div>
                          <span style={{ fontSize: 10, fontWeight: 700, background: '#fee2e2', padding: '2px 8px', borderRadius: 10, color: '#b91c1c' }}>
                            {flag.severity}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommended Safety Precautions */}
                {analysisResult.safety_tips?.length > 0 && (
                  <div>
                    <h3 style={{ fontSize: 14.5, fontWeight: 700, color: '#0f172a', marginBottom: 10 }}>
                      Safety Recommendations
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {analysisResult.safety_tips.map((tip, idx) => (
                        <div
                          key={idx}
                          style={{
                            display: 'flex',
                            alignItems: 'flex-start',
                            gap: 10,
                            padding: '10px 14px',
                            borderRadius: 8,
                            background: '#f0fdf4',
                            border: '1px solid #dcfce7',
                            fontSize: 13,
                            color: '#166534',
                            lineHeight: 1.5,
                          }}
                        >
                          <CheckCircleIcon size={16} color="#16a34a" />
                          <span>{tip}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </>
            );
          })()}
        </div>
      ) : (
        /* ─────────────────────────────────────────────────────────────
            3. UNIFIED 3-IN-1 SCANNER TAB INTERFACE
        ───────────────────────────────────────────────────────────── */
        <div className="card fade-up" style={{ padding: '28px 32px', background: '#ffffff', border: '1px solid rgba(99, 102, 241, 0.16)' }}>
          {/* Navigation Tabs Header */}
          <div
            style={{
              display: 'flex',
              borderBottom: '1px solid rgba(99, 102, 241, 0.14)',
              gap: 8,
              marginBottom: 24,
            }}
          >
            <button
              onClick={() => handleTabSwitch('text')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                padding: '12px 18px',
                background: 'none',
                border: 'none',
                borderBottom: activeTab === 'text' ? '2.5px solid #6366f1' : '2.5px solid transparent',
                color: activeTab === 'text' ? '#6366f1' : '#64748b',
                fontFamily: 'var(--font-heading)',
                fontSize: 14,
                fontWeight: activeTab === 'text' ? 700 : 500,
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
            >
              <MessageSquareIcon size={17} color="currentColor" />
              <span>Text Analysis</span>
            </button>

            <button
              onClick={() => handleTabSwitch('url')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                padding: '12px 18px',
                background: 'none',
                border: 'none',
                borderBottom: activeTab === 'url' ? '2.5px solid #6366f1' : '2.5px solid transparent',
                color: activeTab === 'url' ? '#6366f1' : '#64748b',
                fontFamily: 'var(--font-heading)',
                fontSize: 14,
                fontWeight: activeTab === 'url' ? 700 : 500,
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
            >
              <GlobeIcon size={17} color="currentColor" />
              <span>URL Analysis</span>
            </button>

            <button
              onClick={() => handleTabSwitch('image')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                padding: '12px 18px',
                background: 'none',
                border: 'none',
                borderBottom: activeTab === 'image' ? '2.5px solid #6366f1' : '2.5px solid transparent',
                color: activeTab === 'image' ? '#6366f1' : '#64748b',
                fontFamily: 'var(--font-heading)',
                fontSize: 14,
                fontWeight: activeTab === 'image' ? 700 : 500,
                cursor: 'pointer',
                transition: 'all 0.2s',
              }}
            >
              <ImageIcon size={17} color="currentColor" />
              <span>Image Analysis (OCR)</span>
            </button>
          </div>

          {/* Error Message Alert */}
          {errorMessage && (
            <div
              style={{
                padding: '12px 16px',
                background: '#fef2f2',
                border: '1px solid #fecaca',
                borderRadius: 10,
                color: '#b91c1c',
                fontSize: 13,
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                marginBottom: 20,
              }}
            >
              <AlertTriangleIcon size={16} color="#ef4444" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* ─────────────────────────────────────────────────────────────
              TAB A: TEXT ANALYSIS
          ───────────────────────────────────────────────────────────── */}
          {activeTab === 'text' && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12, flexWrap: 'wrap', gap: 10 }}>
                <label style={{ fontSize: 13, fontWeight: 700, color: '#334155' }}>
                  Suspicious Message or Job Description
                </label>
                <select
                  defaultValue=""
                  onChange={handleDatasetSelect}
                  style={{
                    padding: '6px 12px',
                    borderRadius: 8,
                    border: '1px solid rgba(99, 102, 241, 0.2)',
                    fontSize: 12,
                    background: '#f8f7ff',
                    color: '#475569',
                    cursor: 'pointer',
                    outline: 'none',
                  }}
                >
                  {TEST_DATASETS.map((d, i) => (
                    <option key={i} value={d.value}>
                      {d.label}
                    </option>
                  ))}
                </select>
              </div>

              <textarea
                value={textInput}
                onChange={(e) => {
                  setTextInput(e.target.value);
                  setErrorMessage('');
                }}
                rows={8}
                placeholder="Paste a suspicious SMS, WhatsApp message, recruitment email, job posting or payment request here..."
                style={{
                  width: '100%',
                  borderRadius: 10,
                  border: '1.5px solid rgba(99, 102, 241, 0.18)',
                  padding: '14px 16px',
                  fontSize: 13.5,
                  lineHeight: 1.6,
                  color: '#0f172a',
                  background: '#faf9ff',
                  outline: 'none',
                  resize: 'vertical',
                  boxSizing: 'border-box',
                }}
              />

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 14 }}>
                <span style={{ fontSize: 12, color: '#94a3b8' }}>
                  {textInput.length} characters
                </span>

                <div style={{ display: 'flex', gap: 10 }}>
                  {textInput && (
                    <button
                      onClick={() => setTextInput('')}
                      style={{
                        padding: '9px 16px',
                        borderRadius: 30,
                        border: '1px solid rgba(99, 102, 241, 0.2)',
                        background: '#ffffff',
                        fontSize: 12.5,
                        fontWeight: 600,
                        color: '#64748b',
                        cursor: 'pointer',
                      }}
                    >
                      Clear
                    </button>
                  )}
                  <button
                    onClick={handleAnalyzeText}
                    disabled={analyzing || !textInput.trim()}
                    className="btn-primary"
                    style={{
                      padding: '10px 24px',
                      fontSize: 13,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 8,
                      opacity: analyzing || !textInput.trim() ? 0.6 : 1,
                      cursor: analyzing || !textInput.trim() ? 'not-allowed' : 'pointer',
                    }}
                  >
                    <span>{analyzing ? 'Analyzing Message...' : 'Analyse Text'}</span>
                    <ArrowRightIcon size={14} color="#ffffff" />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* ─────────────────────────────────────────────────────────────
              TAB B: URL ANALYSIS
          ───────────────────────────────────────────────────────────── */}
          {activeTab === 'url' && (
            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 700, color: '#334155', marginBottom: 8 }}>
                Website or Link Address to Examine
              </label>

              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                <div style={{ flex: 1, minWidth: 260, position: 'relative' }}>
                  <input
                    type="url"
                    value={urlInput}
                    onChange={(e) => {
                      setUrlInput(e.target.value);
                      setErrorMessage('');
                    }}
                    placeholder="https://verify-account-update.xyz/login"
                    style={{
                      width: '100%',
                      borderRadius: 10,
                      border: '1.5px solid rgba(99, 102, 241, 0.18)',
                      padding: '12px 16px',
                      fontSize: 13.5,
                      color: '#0f172a',
                      background: '#faf9ff',
                      outline: 'none',
                      boxSizing: 'border-box',
                    }}
                  />
                </div>

                <button
                  onClick={handleAnalyzeUrl}
                  disabled={analyzing || !urlInput.trim()}
                  className="btn-primary"
                  style={{
                    padding: '12px 24px',
                    fontSize: 13,
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 8,
                    opacity: analyzing || !urlInput.trim() ? 0.6 : 1,
                    cursor: analyzing || !urlInput.trim() ? 'not-allowed' : 'pointer',
                  }}
                >
                  <span>{analyzing ? 'Analyzing URL...' : 'Analyse URL'}</span>
                  <ArrowRightIcon size={14} color="#ffffff" />
                </button>
              </div>

              <div style={{ marginTop: 14, fontSize: 12, color: '#94a3b8', lineHeight: 1.6 }}>
                💡 Analyzes domain TLDs, punycode disguises, brand impersonation substrings, and path anomalies without visiting or executing the destination.
              </div>
            </div>
          )}

          {/* ─────────────────────────────────────────────────────────────
              TAB C: IMAGE ANALYSIS (OCR)
          ───────────────────────────────────────────────────────────── */}
          {activeTab === 'image' && (
            <div>
              <label style={{ display: 'block', fontSize: 13, fontWeight: 700, color: '#334155', marginBottom: 8 }}>
                Upload Screenshot (WhatsApp, SMS, Telegram, or Job Posting)
              </label>

              <div
                onClick={() => fileRef.current?.click()}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragOver(false);
                  handleImageFile(e.dataTransfer.files[0]);
                }}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragOver(true);
                }}
                onDragLeave={() => setDragOver(false)}
                style={{
                  border: `2px dashed ${dragOver ? '#6366f1' : 'rgba(99, 102, 241, 0.25)'}`,
                  borderRadius: 12,
                  padding: '32px 20px',
                  textAlign: 'center',
                  cursor: 'pointer',
                  background: dragOver ? 'rgba(99, 102, 241, 0.05)' : '#faf9ff',
                  transition: 'all 0.2s',
                }}
              >
                {selectedImage ? (
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                    <img
                      src={selectedImage}
                      alt="Uploaded Screenshot"
                      style={{ maxHeight: 180, maxWidth: '100%', objectFit: 'contain', borderRadius: 8, marginBottom: 12, border: '1px solid rgba(99, 102, 241, 0.15)' }}
                    />
                    <span style={{ fontSize: 12, color: '#6366f1', fontWeight: 600 }}>
                      Click or drag to replace screenshot
                    </span>
                  </div>
                ) : (
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'center', marginBottom: 10, color: '#6366f1' }}>
                      <ImageIcon size={36} color="#6366f1" />
                    </div>
                    <p style={{ fontSize: 13.5, fontWeight: 600, color: '#334155', margin: '0 0 4px' }}>
                      Drag and drop an image screenshot here, or click to browse
                    </p>
                    <p style={{ fontSize: 12, color: '#94a3b8', margin: 0 }}>
                      Supports PNG, JPG, JPEG up to 10MB
                    </p>
                  </div>
                )}
              </div>

              <input
                ref={fileRef}
                type="file"
                accept="image/png,image/jpeg,image/jpg,image/webp"
                style={{ display: 'none' }}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleImageFile(f);
                  e.target.value = '';
                }}
              />

              {/* OCR Progress Meter */}
              {ocrLoading && (
                <div style={{ marginTop: 16 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: '#64748b', marginBottom: 6 }}>
                    <span>Extracting text from screenshot via OCR...</span>
                    <strong style={{ color: '#6366f1' }}>{ocrProgress}%</strong>
                  </div>
                  <div style={{ height: 6, borderRadius: 10, background: '#e2e8f0', overflow: 'hidden' }}>
                    <div style={{ width: `${ocrProgress}%`, height: '100%', background: 'linear-gradient(90deg, #6366f1, #ec4899)', transition: 'width 0.25s' }} />
                  </div>
                </div>
              )}

              {/* OCR Extracted Text Preview & Action */}
              {ocrExtractedText && !ocrLoading && (
                <div style={{ marginTop: 20 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: '#16a34a' }}>
                      ✓ Text Extracted from Image
                    </span>
                    <span style={{ fontSize: 11, color: '#94a3b8' }}>
                      {ocrExtractedText.length} characters
                    </span>
                  </div>

                  <div
                    style={{
                      padding: '12px 14px',
                      background: '#f0fdf4',
                      border: '1px solid #bbf7d0',
                      borderRadius: 8,
                      fontSize: 12.5,
                      color: '#166534',
                      lineHeight: 1.6,
                      maxHeight: 120,
                      overflowY: 'auto',
                      marginBottom: 16,
                      whiteSpace: 'pre-wrap',
                    }}
                  >
                    {ocrExtractedText}
                  </div>

                  <button
                    onClick={handleAnalyzeImage}
                    disabled={analyzing}
                    className="btn-primary"
                    style={{
                      padding: '10px 24px',
                      fontSize: 13,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 8,
                    }}
                  >
                    <span>{analyzing ? 'Analyzing Extracted Text...' : 'Analyse Extracted Text'}</span>
                    <ArrowRightIcon size={14} color="#ffffff" />
                  </button>
                </div>
              )}

              {ocrHookError && !ocrLoading && (
                <div style={{ marginTop: 12, fontSize: 12, color: '#dc2626' }}>
                  ⚠️ {ocrHookError}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
