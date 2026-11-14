import { createServer } from 'vite';
import React from 'react';
import { renderToString } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';

async function runTests() {
  const server = await createServer({
    server: { middlewareMode: true },
    appType: 'custom',
  });

  const { default: Results } = await server.ssrLoadModule('/src/pages/Results.jsx');

  const testCases = [
    {
      name: 'url/Unverified-zero-score',
      state: {
        result: {
          input_type: 'URL',
          url: 'https://stick.example.com/?lazy=better',
          url_verdict: 'Unverified',
          url_verdict_reason: 'Reserved example domain',
          risk_score: 0,
          url_score: 0,
          risk_level: 'UNVERIFIED',
          indicators: [],
          verification_checks: [
            { name: 'DNS Resolution', status: 'not_performed', details: 'Reserved domain' }
          ],
        }
      },
      assert: (html) => {
        if (!html.includes('Domain Not Verified')) throw new Error('Expected "Domain Not Verified"');
        if (!html.includes('Not scored')) throw new Error('Expected "Not scored" instead of 0 in gauge');
        if (!html.includes('UNVERIFIED')) throw new Error('Expected "UNVERIFIED" badge');
        if (!html.includes('No threat indicators found')) throw new Error('Expected "No threat indicators found" when 0 indicators');
        if (!html.includes('URL Verification Status')) throw new Error('Expected URL Verification Status block');
        if (html.includes('Clean scan')) throw new Error('URL scan must NEVER say "Clean scan"');
        if (html.includes('unknown senders')) throw new Error('URL scan must NEVER say "unknown senders"');
      }
    },
    {
      name: 'url/Unverified-with-caution-indicator',
      state: {
        result: {
          input_type: 'URL',
          url: 'https://safe-looking.com/?next=https://evil.com',
          url_verdict: 'Unverified',
          url_verdict_reason: 'Identified 1 caution indicator: external redirect',
          risk_score: 20,
          url_score: 20,
          risk_level: 'UNVERIFIED',
          indicators: [
            { id: 'external_redirect_param', severity: 'medium', points: 20, description: 'Redirect parameter', value: 'next=https://evil.com' }
          ],
          verification_checks: [
            { name: 'DNS Resolution', status: 'failed', details: 'NXDOMAIN' },
            { name: 'TLS Certificate', status: 'not_performed', details: 'Skipped: host DNS did not resolve' }
          ],
        }
      },
      assert: (html) => {
        if (!html.includes('Domain Not Verified')) throw new Error('Expected "Domain Not Verified"');
        if (html.includes('No threat indicators found')) throw new Error('Must NOT say "No threat indicators found" when caution indicators exist');
        if (!html.includes('1 caution indicator found')) throw new Error('Expected "1 caution indicator found — not verified"');
        if (!html.includes('20')) throw new Error('Expected score 20 to render');
        if (!html.includes('MEDIUM')) throw new Error('Expected MEDIUM badge for redirect indicator');
      }
    },
    {
      name: 'url/Suspicious-amber-35',
      state: {
        result: {
          input_type: 'URL',
          url: 'https://flipkart-store.com/',
          url_verdict: 'Suspicious / Potentially Fraudulent',
          url_verdict_reason: 'Brand lookalike domain',
          risk_score: 35,
          url_score: 35,
          risk_level: 'MEDIUM',
          indicators: [
            { id: 'brand_lookalike_domain', severity: 'high', points: 35, description: 'Brand lookalike', value: 'flipkart-store.com' }
          ],
          verification_checks: [
            { name: 'DNS Resolution', status: 'performed', details: 'Resolved' }
          ],
        }
      },
      assert: (html) => {
        if (!html.includes('Suspicious / Potentially Fraudulent')) throw new Error('Expected "Suspicious / Potentially Fraudulent" title');
        if (!html.includes('SUSPICIOUS')) throw new Error('Expected "SUSPICIOUS" amber badge for score 35');
        if (html.includes('>HIGH RISK<')) throw new Error('Must NOT show HIGH RISK badge for score 35');
      }
    },
    {
      name: 'url/Suspicious-red-70-plus',
      state: {
        result: {
          input_type: 'URL',
          url: 'https://paypa1-secure-login.com/',
          url_verdict: 'Suspicious / Potentially Fraudulent',
          url_verdict_reason: 'Critical lookalike domain',
          risk_score: 70,
          url_score: 70,
          risk_level: 'HIGH',
          indicators: [
            { id: 'brand_lookalike_domain', severity: 'critical', points: 70, description: 'Critical lookalike', value: 'paypa1-secure-login.com' }
          ],
          verification_checks: [
            { name: 'DNS Resolution', status: 'performed', details: 'Resolved' }
          ],
        }
      },
      assert: (html) => {
        if (!html.includes('Suspicious / Potentially Fraudulent')) throw new Error('Expected "Suspicious / Potentially Fraudulent" title');
        if (!html.includes('HIGH RISK')) throw new Error('Expected "HIGH RISK" red badge for score 70+');
        if (!html.includes('CRITICAL')) throw new Error('Expected CRITICAL indicator badge');
      }
    },
    {
      name: 'url/Likely Legitimate',
      state: {
        result: {
          input_type: 'URL',
          url: 'https://example-shop.com/',
          url_verdict: 'Likely Legitimate',
          url_verdict_reason: 'Domain passed verification',
          risk_score: 0,
          url_score: 0,
          risk_level: 'LOW',
          indicators: [],
          verification_checks: [
            { name: 'TLS Certificate', status: 'performed', details: 'Valid' }
          ],
        }
      },
      assert: (html) => {
        if (html.includes('Domain Not Verified')) throw new Error('Did not expect "Domain Not Verified"');
        if (html.includes('Verified / Lower Threat Level')) throw new Error('URL must NEVER say "Verified / Lower Threat Level"');
        if (!html.includes('Likely legitimate - basic checks passed; this is not a guarantee of safety')) {
          throw new Error('Expected Likely Legitimate subtitle wording');
        }
        if (html.includes('Clean scan')) throw new Error('URL scan must NEVER say "Clean scan"');
        if (html.includes('unknown senders')) throw new Error('URL scan must NEVER say "unknown senders"');
      }
    },
    {
      name: 'text/HIGH',
      state: {
        result: {
          input_type: 'Text / Message',
          jobText: 'Urgent hiring! Send money now.',
          risk_score: 100,
          risk_level: 'HIGH',
          rule_score: 100,
          ml_score: 98,
          llm_score: 85,
          scam_category: 'Fake Job Posting',
          url_verdict: null,
          rule_flags: ['Urgent hiring', 'Payment requested'],
          radar_indicators: {
            urgency: 100,
            payment: 90,
            ml_score: 98,
            impersonation: 50,
          }
        }
      },
      assert: (html) => {
        if (html.includes('Domain Not Verified')) throw new Error('text/HIGH must NEVER show "Domain Not Verified"');
        if (!html.includes('Critical Fraud Risk Detected')) throw new Error('Expected "Critical Fraud Risk Detected"');
        if (!html.includes('strong indicators of fraud detected')) {
          throw new Error('Expected "strong indicators of fraud detected" in text/HIGH subtitle');
        }
        if (html.includes('were confirmed')) throw new Error('text/HIGH must NOT say "were confirmed"');
        if (html.includes('URL Verification Status')) throw new Error('text/HIGH must NOT show URL Verification Status');
        if (html.includes('URL Risk</span>')) throw new Error('text/HIGH must NOT show URL Risk axis in radar');
      }
    },
    {
      name: 'text/LOW',
      state: {
        result: {
          input_type: 'Text / Message',
          jobText: 'Standard corporate communication.',
          risk_score: 15,
          risk_level: 'LOW',
          rule_score: 15,
          ml_score: 10,
          llm_score: 10,
          scam_category: 'Unclassified',
          url_verdict: null,
          rule_flags: [],
          radar_indicators: {
            urgency: 0,
            payment: 0,
            ml_score: 10,
            impersonation: 0,
          }
        }
      },
      assert: (html) => {
        if (html.includes('Domain Not Verified')) throw new Error('text/LOW must NEVER show "Domain Not Verified"');
        if (html.includes('Verified / Lower Threat Level')) {
          throw new Error('Text scans must NEVER say "Verified / Lower Threat Level"');
        }
        if (!html.includes('Lower threat level - no strong scam indicators found')) {
          throw new Error('Expected "Lower threat level - no strong scam indicators found"');
        }
        if (html.includes('URL Verification Status')) throw new Error('text/LOW must NOT show URL Verification Status');
        if (html.includes('URL Risk</span>')) throw new Error('text/LOW must NOT show URL Risk axis in radar');
      }
    },
    {
      name: 'ocr/HIGH',
      state: {
        result: {
          input_type: 'Screenshot OCR',
          scannedText: 'Online Job Portal. Urgent requirement. Send CV to WhatsApp.',
          risk_score: 80,
          risk_level: 'HIGH',
          rule_score: 45,
          ml_score: 20,
          llm_score: 80,
          scam_category: 'Potential Recruitment Scam',
          url_verdict: null,
          rule_flags: ['Online Job Portal', 'WhatsApp CV'],
          radar_indicators: {
            urgency: 45,
            payment: 0,
            ml_score: 20,
            impersonation: 60,
          }
        }
      },
      assert: (html) => {
        if (html.includes('Domain Not Verified')) throw new Error('ocr/HIGH must NEVER show "Domain Not Verified"');
        if (!html.includes('Critical Fraud Risk Detected')) throw new Error('Expected "Critical Fraud Risk Detected"');
        if (!html.includes('strong indicators of fraud detected')) {
          throw new Error('Expected "strong indicators of fraud detected" in ocr/HIGH subtitle');
        }
        if (html.includes('were confirmed')) throw new Error('ocr/HIGH must NOT say "were confirmed"');
        if (html.includes('URL Verification Status')) throw new Error('ocr/HIGH must NOT show URL Verification Status');
        if (html.includes('URL Risk</span>')) throw new Error('ocr/HIGH must NOT show URL Risk axis in radar');
      }
    },
  ];

  let passed = 0;
  for (const tc of testCases) {
    try {
      const element = React.createElement(
        MemoryRouter,
        { initialEntries: [{ pathname: '/results', state: tc.state }] },
        React.createElement(Results)
      );
      const html = renderToString(element);
      tc.assert(html);
      console.log(`PASS: ${tc.name}`);
      passed++;
    } catch (err) {
      console.error(`FAIL: ${tc.name} -> ${err.message}`);
    }
  }

  await server.close();
  console.log(`\nFrontend Results Test Summary: ${passed}/${testCases.length} passed.`);
  if (passed !== testCases.length) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Fatal error running tests:', err);
  process.exit(1);
});
