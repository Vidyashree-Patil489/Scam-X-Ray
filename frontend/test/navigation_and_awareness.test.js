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
let Dashboard;
let Home;

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

  const dashMod = await server.ssrLoadModule('./src/pages/Dashboard.jsx');
  Dashboard = dashMod.default;

  const homeMod = await server.ssrLoadModule('./src/pages/Home.jsx');
  Home = homeMod.default;
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

test('Dashboard renders only Scam Detection and AI Image Detection tools, no history link', () => {
  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: ['/dashboard'] },
      React.createElement(Dashboard)
    )
  );

  // Tool cards
  assert.ok(html.includes('Scam Detection'));
  assert.ok(html.includes('AI Image Detection'));
  assert.equal(html.includes('Steganography Scanner'), false);
  assert.equal(html.includes('Fact Checker'), false);

  // Quick Access
  assert.ok(html.includes('Security Awareness'));
  assert.equal(html.includes('Scan History'), false);

  // Recent Activity
  assert.equal(html.includes('View All History'), false);
  assert.ok(html.includes('Completed investigations across all four threat engines will be automatically archived here.'));
});

test('Home page renders updated copy, 2 detection engines, and no removed features', () => {
  const html = ReactDOMServer.renderToStaticMarkup(
    React.createElement(
      MemoryRouter,
      { initialEntries: ['/'] },
      React.createElement(Home)
    )
  );

  // Hero
  assert.ok(html.includes('From suspicious messages and links to AI-generated images, ScamXRay brings powerful digital threat analysis tools together in one place.'));
  assert.ok(html.includes('>2<') && html.includes('Detection Engines'));
  assert.equal(html.includes('Forensic Modules'), false);

  // Floating tags
  assert.equal(html.includes('Hidden Payload Check'), false);
  assert.ok(html.includes('Threat Detected'));
  assert.ok(html.includes('Suspicious URL'));
  assert.ok(html.includes('AI Media Analysis'));

  // Section heading and subtitle
  assert.ok(html.includes('One Platform. Two Layers of Digital Protection.'));
  assert.equal(html.includes('Four Layers'), false);
  assert.ok(html.includes('A centralized digital safety platform designed to identify deceptive interactions across communications and media.'));

  // Tool cards in Home
  assert.ok(html.includes('Scam Detection'));
  assert.ok(html.includes('AI Image Detection'));
  assert.equal(html.includes('Steganography Scanner'), false);
  assert.equal(html.includes('Fact Checker'), false);

  // How ScamXRay Works steps
  assert.ok(html.includes('Paste suspicious text, submit a link, or upload an image file.'));
  assert.ok(html.includes('The dedicated engine analyzes heuristic rules, ML models, URL checks, or image signals.'));

  // Why Consolidate Threat Verification cards
  assert.ok(html.includes('Modern digital attacks rarely rely on a single vector. Fraudsters combine smishing, deceptive links, and synthetic media to build false credibility.'));
  assert.ok(html.includes('Verify an internship message, scan its included link, and inspect an attached poster screenshot without juggling separate disjointed tools.'));
  assert.ok(html.includes('Rather than returning an opaque black-box score, ScamXRay outlines exact matched heuristic rules, URL checks, or image-analysis signals.'));
  assert.ok(html.includes('Scans operate without mandatory user tracking or credentials. No account or sign-in is needed to run a scan.'));

  // CTA
  assert.ok(html.includes('Access both digital threat intelligence engines instantly in your browser.'));

  // Footer
  assert.ok(html.includes('Intelligent digital safety platform unifying scam detection and synthetic media analysis.'));
  assert.equal(html.includes('forensic steganography'), false);
  assert.equal(html.includes('factual claim verification'), false);
});
