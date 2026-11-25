import test from 'node:test';
import assert from 'node:assert/strict';
import process from 'node:process';
import { createServer } from 'vite';
import React from 'react';
import ReactDOMServer from 'react-dom/server';

let server;
let HighlightedText;

test.before(async () => {
  server = await createServer({
    root: process.cwd(),
    server: { middlewareMode: true },
  });
  const mod = await server.ssrLoadModule('./src/pages/Results.jsx');
  HighlightedText = mod.HighlightedText;
});

test.after(async () => {
  if (server) {
    await server.close();
  }
});

function extractMarks(html) {
  const markRegex = /<mark\b[^>]*>(.*?)<\/mark>/gs;
  const matches = [];
  let match;
  while ((match = markRegex.exec(html)) !== null) {
    matches.push(match[1]);
  }
  return matches;
}

test('Emoji before phrases (🔴, ✅, 📲, ₹) -> full phrases covered exactly', () => {
  const sampleText =
    '🔴 URGENT HIRING 🔴\n\n' +
    'Work From Home Opportunity!!\n' +
    'Earn ₹45,000 - ₹50,000 Per Week\n' +
    '✅ No Experience Required\n' +
    '✅ No Interview\n' +
    '✅ Immediate Joining\n' +
    '✅ Part Time / Full Time\n\n' +
    'Registration Fee: ₹499 only\n' +
    '(Refundable after 1st salary)\n\n' +
    'Contact HR: +91 98765 4321 0\n' +
    'WhatsApp Only 📲\n\n' +
    '⚠️ Limited Seats Available\n' +
    'Apply Before 6PM Today!!';

  const matches = [
    { rule: 'Urgency or threat', spans: [{ start: 2, end: 8 }], severity: 12 },
    { rule: 'Unexpected payment request', spans: [{ start: 165, end: 181 }], severity: 25 },
    { rule: 'Suspicious job offer', spans: [{ start: 82, end: 104 }], severity: 18 },
    { rule: 'Suspicious communication channel', spans: [{ start: 253, end: 266 }], severity: 12 },
    { rule: 'Upfront fee for a job', spans: [{ start: 165, end: 181 }], severity: 35 },
  ];

  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(HighlightedText, { text: sampleText, matches })
  );

  const marks = extractMarks(html);
  assert.deepEqual(marks, [
    'URGENT',
    'No Experience Required',
    'Registration Fee',
    'WhatsApp Only',
  ]);

  // Ensure no empty marks
  assert.equal(marks.some((m) => m.trim().length === 0), false);
});

test('Multi-code-point emoji sequence (e.g. 👨👩👧) before a phrase', () => {
  const text = '👨👩👧 URGENT HIRING 👨‍👩‍👧\nRegistration Fee: ₹499 only';
  // Code points:
  // 👨 (1), 👩 (1), 👧 (1), ' ' (1) -> 'URGENT' starts at 4, ends at 10
  // ' HIRING ' (8), 👨‍👩‍👧 (5), '\n' (1) -> 'Registration Fee' starts at 24, ends at 40
  const matches = [
    { rule: 'Urgency or threat', spans: [{ start: 4, end: 10 }], severity: 12 },
    { rule: 'Unexpected payment request', spans: [{ start: 24, end: 40 }], severity: 25 },
  ];

  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(HighlightedText, { text, matches })
  );

  const marks = extractMarks(html);
  assert.deepEqual(marks, ['URGENT', 'Registration Fee']);
});

test('CRLF line breaks preserve character-for-character highlight spans', () => {
  const sampleCrlf =
    '🔴 URGENT HIRING 🔴\r\n' +
    '✅ No Experience Required\r\n' +
    'Registration Fee: ₹499 only\r\n' +
    'WhatsApp Only 📲';

  // In CRLF text:
  // '🔴 ' (2) -> URGENT is 2..8
  // ' HIRING 🔴\r\n✅ ' (13) -> No Experience Required is 21..43
  // '\r\n' (2) -> Registration Fee is 45..61
  // ': ₹499 only\r\n' (13) -> WhatsApp Only is 74..87
  const matches = [
    { rule: 'Urgency', spans: [{ start: 2, end: 8 }], severity: 12 },
    { rule: 'Job Offer', spans: [{ start: 21, end: 43 }], severity: 18 },
    { rule: 'Fee', spans: [{ start: 45, end: 61 }], severity: 25 },
    { rule: 'Channel', spans: [{ start: 74, end: 87 }], severity: 12 },
  ];

  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(HighlightedText, { text: sampleCrlf, matches })
  );

  const marks = extractMarks(html);
  assert.deepEqual(marks, [
    'URGENT',
    'No Experience Required',
    'Registration Fee',
    'WhatsApp Only',
  ]);
});

test('Zero-length and out-of-range spans are skipped with no empty highlight elements', () => {
  const text = '🔴 URGENT HIRING';
  const matches = [
    { rule: 'Valid', spans: [{ start: 2, end: 8 }], severity: 12 },
    { rule: 'ZeroLength', spans: [{ start: 4, end: 4 }], severity: 12 },
    { rule: 'NegativeStart', spans: [{ start: -5, end: 5 }], severity: 12 },
    { rule: 'OutOfRange', spans: [{ start: 50, end: 60 }], severity: 12 },
    { rule: 'Inverted', spans: [{ start: 8, end: 2 }], severity: 12 },
  ];

  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(HighlightedText, { text, matches })
  );

  const marks = extractMarks(html);
  assert.deepEqual(marks, ['URGENT']);
  assert.equal(html.includes('<mark></mark>'), false);
  assert.equal(html.includes('style=""'), false);
});
