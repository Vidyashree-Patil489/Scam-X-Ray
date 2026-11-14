import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Navbar from './Navbar';

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div
      style={{
        minHeight: '100vh',
        background: 'var(--bg, #f8f7ff)',
        display: 'flex',
      }}
    >
      {/* Persistent Sidebar */}
      <Sidebar
        collapsed={collapsed}
        setCollapsed={setCollapsed}
        mobileOpen={mobileOpen}
        setMobileOpen={setMobileOpen}
      />

      {/* Main Content Area */}
      <div
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          marginLeft: collapsed ? 76 : 256,
          transition: 'margin-left 0.25s cubic-bezier(0.4, 0, 0.2, 1)',
          minWidth: 0,
        }}
        className="main-layout-content"
      >
        {/* Top Navbar */}
        <Navbar
          mobileOpen={mobileOpen}
          setMobileOpen={setMobileOpen}
        />

        {/* Dynamic page content with comfortable clearance below navbar */}
        <main
          style={{
            flex: 1,
            padding: '36px 36px 56px',
            maxWidth: 1240,
            width: '100%',
            margin: '0 auto',
            boxSizing: 'border-box',
          }}
          className="layout-page-container"
        >
          <Outlet />
        </main>
      </div>
    </div>
  );
}
