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
      name: 'url/Suspicious-amber-35',
      state: {
        result: {
          input_type: 'URL',
          url: 'https://flipkart-store.com/',
          url_verdict: 'Suspicious',
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
        if (!html.includes('Suspicious')) throw new Error('Expected "Suspicious" title');
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
          url_verdict: 'Suspicious',
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
        if (!html.includes('Suspicious')) throw new Error('Expected "Suspicious" title');
        if (!html.includes('HIGH RISK')) throw new Error('Expected "HIGH RISK" red badge for score 70+');
        if (!html.includes('CRITICAL')) throw new Error('Expected CRITICAL indicator badge');
      }
    },
    {
      name: 'url/reputation-match-found',
      state: {
        result: {
          input_type: 'URL',
          url: 'https://phish-login.example.com/',
          url_verdict: 'Malicious',
          url_verdict_reason: 'Matched active OpenPhish community feed entry',
          risk_score: 100,
          url_score: 100,
          risk_level: 'HIGH',
          indicators: [
            { id: 'openphish_reputation_match', severity: 'critical', points: 100, description: 'Critical lookalike domain', value: 'phish-login.example.com' }
          ],
          verification_checks: [
            { name: 'DNS Resolution', status: 'performed', details: 'Resolved to 1.2.3.4 (disk_cache)' }
          ],
          evidence: [
            { source: 'OpenPhish Community Feed', status: 'match', result: 'Matched active OpenPhish community feed entry: https://phish-login.example.com (disk_cache)' },
          ],
        }
      },
      assert: (html) => {
        if (!html.includes('Intelligence Sources &amp; Evidence')) throw new Error('Expected "Intelligence Sources & Evidence" section');
        if (!html.includes('OpenPhish Community Feed')) throw new Error('Expected OpenPhish Community Feed');
        if (!html.includes('Match found')) throw new Error('Expected "Match found" badge');
        if (!html.includes('Matched active OpenPhish community feed entry: https://phish-login.example.com')) {
          throw new Error('Expected OpenPhish match detail');
        }
        if (!html.includes('Structural Threat Indicators')) throw new Error('Expected Structural Threat Indicators');
        if (!html.includes('1 found')) throw new Error('Expected "1 found" badge');
        if (!html.includes('Critical lookalike domain')) throw new Error('Expected indicator description');
        if (!html.includes('Infrastructure Evaluations')) throw new Error('Expected Infrastructure Evaluations');
        if (!html.includes('DNS Resolution — Passed — Resolved to 1.2.3.4')) {
          throw new Error('Expected formatted infrastructure check line');
        }
        if (html.includes('(disk_cache)') || html.includes('(stub)') || html.includes('(in_memory)')) {
          throw new Error('Developer cache leak found in rendered HTML');
        }
        if (html.includes('Safe Browsing')) {
          throw new Error('Safe Browsing must NOT appear in rendered HTML');
        }
      }
    },
    {
      name: 'url/reputation-no-match-google',
      state: {
        result: {
          input_type: 'URL',
          url: 'https://google.com/',
          url_verdict: 'No threat found',
          url_verdict_reason: 'Zero threat indicators detected',
          risk_score: 0,
          url_score: 0,
          risk_level: 'LOW',
          indicators: [],
          verification_checks: [
            { name: 'DNS resolution', status: 'performed', details: 'Resolved to 142.250.190.46' },
            { name: 'TLS certificate', status: 'performed', details: 'Valid cert for *.google.com' },
            { name: 'RDAP domain age', status: 'performed', details: 'Domain is 9,876 days old' },
            { name: 'Safe HTTP reachability', status: 'performed', details: 'HTTP 200 OK (0.24s)' }
          ],
          evidence: [
            { source: 'OpenPhish Community Feed', status: 'no_match', result: 'Not listed in OpenPhish community feed (in_memory)' },
          ],
        }
      },
      assert: (html) => {
        if (!html.includes('Intelligence Sources &amp; Evidence')) throw new Error('Expected "Intelligence Sources & Evidence" section');
        if (!html.includes('OpenPhish Community Feed')) throw new Error('Expected OpenPhish Community Feed');
        if (!html.includes('No match')) throw new Error('Expected "No match" badge');
        if (!html.includes('Not listed in the OpenPhish community feed.')) {
          throw new Error('Expected transformed OpenPhish no match text');
        }
        if (!html.includes('Structural Threat Indicators')) throw new Error('Expected Structural Threat Indicators');
        if (!html.includes('None found')) throw new Error('Expected "None found" badge');
        if (!html.includes('Zero heuristic or structural threat indicators detected.')) {
          throw new Error('Expected zero threat indicators detail text');
        }
        if (!html.includes('Infrastructure Evaluations')) throw new Error('Expected Infrastructure Evaluations');
        if (!html.includes('DNS resolution — Passed — Resolved to 142.250.190.46')) {
          throw new Error('Expected DNS resolution check line');
        }
        if (!html.includes('TLS certificate — Passed — Valid cert for *.google.com')) {
          throw new Error('Expected TLS certificate check line');
        }
        if (!html.includes('RDAP domain age — Passed — Domain is 9,876 days old')) {
          throw new Error('Expected RDAP check line');
        }
        if (!html.includes('Safe HTTP reachability — Passed — HTTP 200 OK (0.24s)')) {
          throw new Error('Expected HTTP reachability check line');
        }
        if (html.includes('(in_memory)') || html.includes('(disk_cache)')) {
          throw new Error('Developer cache leaks "(in_memory)" or "(disk_cache)" found in rendered HTML');
        }
        if (html.includes('Safe Browsing')) {
          throw new Error('Safe Browsing must NOT appear in rendered HTML');
        }
      }
    },
    {
      name: 'url/reputation-blocked-private-address',
      state: {
        result: {
          input_type: 'URL',
          url: 'http://127.0.0.1',
          url_verdict: 'Unknown',
          url_verdict_reason: 'The host \'127.0.0.1\' is a private or internal address; ScamXRay does not connect to it.',
          risk_score: 0,
          url_score: 0,
          risk_level: 'UNKNOWN',
          indicators: [],
          verification_checks: [
            { name: 'DNS Resolution', status: 'not_performed', details: 'Blocked: private or internal address; ScamXRay does not connect to it' },
            { name: 'TLS Certificate', status: 'not_performed', details: 'Blocked: private or internal address; ScamXRay does not connect to it' },
            { name: 'Domain Age (RDAP)', status: 'not_performed', details: 'Blocked: private or internal address; ScamXRay does not connect to it' },
            { name: 'HTTP Reachability', status: 'not_performed', details: 'Blocked: private or internal address; ScamXRay does not connect to it' }
          ],
          evidence: [
            { source: 'OpenPhish Community Feed', status: 'not_checked', result: 'Blocked: private or internal address; ScamXRay does not connect to it' },
          ],
        }
      },
      assert: (html) => {
        if (!html.includes('Intelligence Sources &amp; Evidence')) throw new Error('Expected "Intelligence Sources & Evidence" section');
        if (!html.includes('OpenPhish Community Feed')) throw new Error('Expected OpenPhish Community Feed');
        if (!html.includes('Not checked')) throw new Error('Expected "Not checked" badge');
        if (!html.includes('Blocked: private or internal address; ScamXRay does not connect to it')) {
          throw new Error('Expected blocked detail text');
        }
        if (!html.includes('Structural Threat Indicators')) throw new Error('Expected Structural Threat Indicators');
        if (!html.includes('None found')) throw new Error('Expected "None found" badge');
        if (!html.includes('Infrastructure Evaluations')) throw new Error('Expected Infrastructure Evaluations');
        if (!html.includes('No network checks were run.')) {
          throw new Error('Expected "No network checks were run." for blocked private address');
        }
        if (html.includes('Safe Browsing')) {
          throw new Error('Safe Browsing must NOT appear in rendered HTML');
        }
      }
    },
    {
      name: 'url/Malicious',
      state: {
        result: {
          input_type: 'URL',
          url: 'https://phish-login.example.com/',
          url_verdict: 'Malicious',
          url_verdict_reason: 'Matched active OpenPhish community feed entry',
          risk_score: 100,
          url_score: 100,
          risk_level: 'HIGH',
          indicators: [
            { id: 'openphish_reputation_match', severity: 'critical', points: 100, description: 'OpenPhish match', value: 'phish-login.example.com' }
          ],
          verification_checks: [
            { name: 'DNS Resolution', status: 'performed', details: 'Resolved' }
          ],
          evidence: [
            { source: 'OpenPhish Community Feed', result: 'Active phishing entry matched' }
          ],
          limitations: [
            'No match in a feed does not mean the link is safe'
          ]
        }
      },
      assert: (html) => {
        if (!html.includes('MALICIOUS')) throw new Error('Expected "MALICIOUS" badge');
        if (!html.includes('Malicious Link Detected')) throw new Error('Expected "Malicious Link Detected"');
        if (!html.includes('No match in a feed does not mean the link is safe')) throw new Error('Expected feed limitations disclaimer');
      }
    },
    {
      name: 'url/No-threat-found',
      state: {
        result: {
          input_type: 'URL',
          url: 'https://authentic-portal.org/',
          url_verdict: 'No threat found',
          url_verdict_reason: 'The domain completed infrastructure evaluations with zero threat indicators identified.',
          risk_score: 0,
          url_score: 0,
          risk_level: 'LOW',
          indicators: [],
          verification_checks: [
            { check: 'TLS Certificate', name: 'TLS Certificate', status: 'performed', details: 'Valid matching certificate' },
            { check: 'HTTP Reachability', name: 'HTTP Reachability', status: 'performed', details: 'Reachable (HTTP 200)' },
            { check: 'Domain Age (RDAP)', name: 'Domain Age (RDAP)', status: 'not_performed', details: 'Skipped' }
          ],
          limitations: [
            'No match in a feed does not mean the link is safe'
          ]
        }
      },
      assert: (html) => {
        if (!html.includes('NO THREAT FOUND')) throw new Error('Expected "NO THREAT FOUND" badge');
        if (!html.includes('No Threat Found')) throw new Error('Expected "No Threat Found" title');
        // Unperformed checks must be hidden (not showing not_performed or skipped)
        if (html.includes('Domain Age (RDAP)')) throw new Error('Unperformed check should be hidden');
        if (html.includes('TLS Certificate') === false) throw new Error('Performed check should be visible');
      }
    },
    {
      name: 'url/Unknown-zero-score',
      state: {
        result: {
          input_type: 'URL',
          url: 'https://github.com/torvalds/linux',
          url_verdict: 'Unknown',
          url_verdict_reason: "This link is hosted on a user-content platform ('github.com').",
          risk_score: 0,
          url_score: 0,
          risk_level: 'UNKNOWN',
          indicators: [
            { id: 'user_content_platform', severity: 'info', points: 0, description: 'User-content platform', value: 'github.com' }
          ],
          verification_checks: [
            { name: 'DNS Resolution', status: 'performed', details: 'Resolved' }
          ]
        }
      },
      assert: (html) => {
        if (!html.includes('UNKNOWN')) throw new Error('Expected "UNKNOWN" badge');
        if (!html.includes('Status Unknown')) throw new Error('Expected "Status Unknown" title');
        if (!html.includes('Not scored')) throw new Error('Expected "Not scored" in gauge for Unknown with 0 threat score');
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
    {
      name: 'text/amazon-india-highlighting-and-overlap-merge',
      state: {
        result: {
          input_type: 'Text / Message',
          jobText: 'Amazon India\nWork From Home 2026 Recruitment\n@ Salary: Rs.50,000/month\n@ Hours: 2-3 hours daily only\nProcessing Fee: Rs.599 (One Time)\nContact HR Priya: +91 99887 76655\nWhatsApp Only No Calls Please',
          risk_score: 90,
          risk_level: 'HIGH',
          rule_score: 90,
          ml_score: 75,
          llm_score: 85,
          scam_category: 'Fake Job Posting',
          url_verdict: null,
          matches: [
            {
              id: 'unexpected_payment_request',
              rule: 'Unexpected payment request',
              severity: 25,
              severity_label: 'HIGH',
              matched_text: 'Processing Fee',
              spans: [{ start: 101, end: 115 }],
              text: "Unexpected payment request: matched 'Processing Fee'",
            },
            {
              id: 'suspicious_job_offer',
              rule: 'Suspicious job offer',
              severity: 18,
              severity_label: 'CAUTIONARY',
              matched_text: '2-3 hours daily',
              spans: [{ start: 80, end: 95 }],
              text: "Suspicious job offer: matched '2-3 hours daily'",
            },
            {
              id: 'suspicious_communication_channel',
              rule: 'Suspicious communication channel',
              severity: 12,
              severity_label: 'CAUTIONARY',
              matched_text: 'WhatsApp Only',
              spans: [{ start: 169, end: 182 }],
              text: "Suspicious communication channel: matched 'WhatsApp Only'",
            },
            {
              id: 'upfront_fee_for_a_job',
              rule: 'Upfront fee for a job',
              severity: 35,
              severity_label: 'HIGH',
              matched_text: 'Processing Fee',
              spans: [{ start: 101, end: 115 }],
              text: "Upfront fee for a job: matched 'Processing Fee'",
            },
          ],
          rule_flags: [
            "Unexpected payment request: matched 'Processing Fee'",
            "Suspicious job offer: matched '2-3 hours daily'",
            "Suspicious communication channel: matched 'WhatsApp Only'",
            "Upfront fee for a job: matched 'Processing Fee'",
          ],
        }
      },
      assert: (html) => {
        // 1. Detected Flags & Red Flags list has 4 warning indicators
        if (!html.includes('4 warning indicators')) {
          throw new Error('Expected "4 warning indicators" badge');
        }
        if (!html.includes('2-3 hours daily')) {
          throw new Error('Expected real matched wording "2-3 hours daily" in flags list');
        }
        if (!html.includes('Processing Fee')) {
          throw new Error('Expected "Processing Fee" in flags list');
        }

        // 2. Highlighting matches
        if (!html.includes('>2-3 hours daily</mark>')) {
          throw new Error('Expected "2-3 hours daily" to be highlighted');
        }
        if (!html.includes('>Processing Fee</mark>')) {
          throw new Error('Expected "Processing Fee" to be highlighted');
        }
        if (!html.includes('>WhatsApp Only</mark>')) {
          throw new Error('Expected "WhatsApp Only" to be highlighted');
        }

        // 3. Overlap merge for Processing Fee: both flag names must appear in its tooltip / title
        if (!html.includes('Unexpected payment request • Upfront fee for a job') &&
            !html.includes('Unexpected payment request, Upfront fee for a job')) {
          throw new Error('Expected merged Processing Fee highlight to contain both flag names');
        }

        // 4. Overlap merge severity: Processing Fee must have highest severity (HIGH risk red background #fee2e2)
        const feeMarkIndex = html.indexOf('>Processing Fee</mark>');
        const feeMarkTag = html.slice(feeMarkIndex - 300, feeMarkIndex);
        if (!feeMarkTag.includes('#fee2e2')) {
          throw new Error('Processing Fee must use highest severity red background (#fee2e2)');
        }

        // 5. Cautionary severity: 2-3 hours daily must have cautionary orange background (#ffedd5)
        const hoursMarkIndex = html.indexOf('>2-3 hours daily</mark>');
        const hoursMarkTag = html.slice(hoursMarkIndex - 300, hoursMarkIndex);
        if (!hoursMarkTag.includes('#ffedd5')) {
          throw new Error('2-3 hours daily must use cautionary background (#ffedd5)');
        }

        // 6. Nothing without a flag is highlighted
        if (html.includes('>Rs.50,000/month</mark>') || html.includes('>Salary</mark>')) {
          throw new Error('Salary should NOT be highlighted');
        }
        if (html.includes('>Contact HR Priya</mark>') || html.includes('>Priya</mark>')) {
          throw new Error('Contact HR Priya should NOT be highlighted');
        }
        if (html.includes('>No Calls Please</mark>')) {
          throw new Error('No Calls Please should NOT be highlighted');
        }
      }
    },
    {
      name: 'text/highlight-no-spans-unhighlighted',
      state: {
        result: {
          input_type: 'Text / Message',
          jobText: 'Normal message with zero flagged phrases.',
          risk_score: 0,
          risk_level: 'LOW',
          rule_score: 0,
          matches: [],
          rule_flags: [],
        }
      },
      assert: (html) => {
        if (!html.includes('Normal message with zero flagged phrases.')) {
          throw new Error('Expected original text rendered');
        }
        if (html.includes('<mark')) {
          throw new Error('Text with no spans must NOT contain any <mark> highlights');
        }
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
