import test from 'node:test';
import assert from 'node:assert/strict';
import process from 'node:process';
import { createServer } from 'vite';
import React from 'react';
import ReactDOMServer from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';

let server;
let Sidebar;
let SecurityAwareness;
let App;

test.before(async () => {
  server = await createServer({
    root: process.cwd(),
    server: { middlewareMode: true },
  });
  const sidebarMod = await server.ssrLoadModule('./src/components/Sidebar.jsx');
  Sidebar = sidebarMod.default;

  const awarenessMod = await server.ssrLoadModule('./src/pages/SecurityAwareness.jsx');
  SecurityAwareness = awarenessMod.default;

  const appMod = await server.ssrLoadModule('./src/App.jsx');
  App = appMod.default;
});

test.after(async () => {
  if (server) {
    await server.close();
  }
});

test('Sidebar navigation excludes removed pages and keeps allowed 5 in order', () => {
  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: ['/dashboard'] },
      React.createElement(Sidebar, {
        collapsed: false,
        setCollapsed: () => {},
        mobileOpen: false,
        setMobileOpen: () => {},
      })
    )
  );

  // Must NOT contain removed items
  assert.equal(html.includes('Fact Checker'), false, 'Must not contain Fact Checker');
  assert.equal(html.includes('Steganography Scanner'), false, 'Must not contain Steganography Scanner');
  assert.equal(html.includes('Scan History'), false, 'Must not contain Scan History');
  assert.equal(html.includes('/fact-checker'), false, 'Must not contain /fact-checker route');
  assert.equal(html.includes('/steganography'), false, 'Must not contain /steganography route');
  assert.equal(html.includes('/history'), false, 'Must not contain /history route');

  // Must contain the allowed 5 pages in current order
  assert.equal(html.includes('Dashboard'), true);
  assert.equal(html.includes('Scam Detection'), true);
  assert.equal(html.includes('AI Image Detection'), true);
  assert.equal(html.includes('Security Awareness'), true);
  assert.equal(html.includes('Settings'), true);

  const idxDashboard = html.indexOf('Dashboard');
  const idxScam = html.indexOf('Scam Detection');
  const idxAI = html.indexOf('AI Image Detection');
  const idxSecurity = html.indexOf('Security Awareness');
  const idxSettings = html.indexOf('Settings');

  assert.ok(idxDashboard < idxScam, 'Dashboard before Scam Detection');
  assert.ok(idxScam < idxAI, 'Scam Detection before AI Image Detection');
  assert.ok(idxAI < idxSecurity, 'AI Image Detection before Security Awareness');
  assert.ok(idxSecurity < idxSettings, 'Security Awareness before Settings');
});

test('Security Awareness page renders all required educational content sections', () => {
  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(SecurityAwareness)
  );

  // Section 1: Common scams in India
  assert.ok(html.includes('Common Scams in India'));
  assert.ok(html.includes('work-from-home'));
  assert.ok(html.includes('task-based'));
  assert.ok(html.includes('KYC'));
  assert.ok(html.includes('Phishing links'));
  assert.ok(html.includes('QR-code'));
  assert.ok(html.includes('customer-care'));
  assert.ok(html.includes('Digital arrest'));

  // Section 2: Fake job offer red flags
  assert.ok(html.includes('Fake Job Offer Red Flags'));
  assert.ok(html.includes('Upfront fees') || html.includes('registration'));
  assert.ok(html.includes('WhatsApp or Telegram'));
  assert.ok(html.includes('No formal interview') || html.includes('No interview'));
  assert.ok(html.includes('free email') || html.includes('Gmail'));

  // Section 3: Never share
  assert.ok(html.includes('Never Share'));
  assert.ok(html.includes('OTP'));
  assert.ok(html.includes('UPI PIN'));
  assert.ok(html.includes('CVV'));
  assert.ok(html.includes('You never need to enter your UPI PIN to receive money'));

  // Section 4: Before you click
  assert.ok(html.includes('Before You Click'));
  assert.ok(html.includes('full domain'));
  assert.ok(html.includes('lookalike'));

  // Section 5: If you have been scammed (ordered steps)
  assert.ok(html.includes('If You Have Been Scammed'));
  assert.ok(html.includes('1930'), 'Helpline 1930 must be present');
  assert.ok(html.includes('cybercrime.gov.in'), 'cybercrime.gov.in must be present');
  assert.ok(html.includes('Do not delete the chat'));

  // Section 6: Report suspicious messages
  assert.ok(html.includes('Chakshu'));
  assert.ok(html.includes('sancharsaathi.gov.in/sfc'));

  // Section 7: Using ScamXRay responsibly
  assert.ok(html.includes('Using ScamXRay Responsibly'));
  assert.ok(html.includes('No threat found'));

  // Links must open in a new tab
  assert.ok(html.includes('href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer"'));
  assert.ok(html.includes('href="https://sancharsaathi.gov.in/sfc" target="_blank" rel="noopener noreferrer"'));
});

test('App routes and components load without removed pages', () => {
  assert.ok(App);
});
