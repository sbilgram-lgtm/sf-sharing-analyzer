import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { getAuthStatus } from '../services/api';

const STORAGE_KEY = 'sf_sha_credentials';

type Severity = 'critical' | 'high' | 'medium' | 'low';

interface CheckItem {
  title: string;
  severity: Severity;
}

const CATEGORY_CHECKS: Record<string, CheckItem[]> = {
  'OWD Analysis': [
    { title: 'Sensitive Object Is Public Read/Write', severity: 'high' },
    { title: 'Objects Have External OWD Set to Public Read/Write', severity: 'critical' },
    { title: 'Objects Are Publicly Readable by External Users', severity: 'medium' },
    { title: 'Many Objects Have Public Read/Write Internal OWD', severity: 'medium' },
    { title: 'OWD Chain Confusion — Parent Is Private, Child Is Controlled by Parent', severity: 'medium' },
  ],
  'Role Hierarchy': [
    { title: 'Role Hierarchy Exceeds 10 Levels Deep', severity: 'high' },
    { title: 'Role Hierarchy Approaching 7 Level Recommended Maximum', severity: 'medium' },
    { title: 'Total Roles — Large Role Hierarchy (1,000+)', severity: 'high' },
    { title: 'Total Roles — Monitor Role Hierarchy Size (500+)', severity: 'medium' },
    { title: 'Top-Level Roles Have More Than 5 Users', severity: 'medium' },
    { title: 'Role Hierarchy Level Excessively Wide (100+)', severity: 'high' },
    { title: 'Role Hierarchy Level Wide (50+)', severity: 'medium' },
    { title: 'Roles Have No Active Users', severity: 'low' },
  ],
  'Territory Management': [
    { title: 'Multiple Active Territory Models Found', severity: 'high' },
    { title: 'Territories Have No Users Assigned', severity: 'medium' },
    { title: 'Territory Assignment Rules Are Inactive', severity: 'low' },
    { title: 'Users Assigned to Excessive Number of Territories (50+)', severity: 'medium' },
    { title: 'Territory Assignment Rules Lack Filtering Logic', severity: 'low' },
  ],
  'Sharing Rules': [
    { title: 'Sharing Rules Target All Internal Users', severity: 'high' },
    { title: 'Total Sharing Rules — Recalculation Risk (500+)', severity: 'high' },
    { title: 'Object Approaching 300 Sharing Rules Platform Limit (250+)', severity: 'high' },
    { title: 'Total Sharing Rules — Review for Redundancy (200+)', severity: 'medium' },
    { title: 'Object Has High Number of Sharing Rules (100+)', severity: 'medium' },
    { title: 'Object Approaching 50 Criteria-Based Sharing Rule Limit (40+)', severity: 'medium' },
    { title: 'Restriction Rules Configured — Review Access Restrictions', severity: 'low' },
    { title: 'No Restriction Rules Configured — Evaluate Opportunity', severity: 'low' },
    { title: "Sharing Rules Are Redundant with Object's Public OWD", severity: 'low' },
  ],
  'Manual Sharing': [
    { title: 'Object Has Very High Manual Share Volume (10,000+)', severity: 'high' },
    { title: 'Object Has High Manual Share Volume (1,000+)', severity: 'medium' },
    { title: 'Private OWD Object Relies Heavily on Manual Sharing (500+)', severity: 'medium' },
  ],
  'Apex Sharing': [
    { title: 'Many Apex Classes Run Without Sharing Enforcement (20+)', severity: 'high' },
    { title: 'Many Apex Classes Have No Sharing Declaration (50+)', severity: 'high' },
    { title: 'Apex Classes Run Without Sharing Enforcement (5+)', severity: 'medium' },
    { title: 'Apex Classes Have No Sharing Declaration', severity: 'medium' },
    { title: 'Apex-Managed Share Records Exceed 5,000 on an Object', severity: 'medium' },
    { title: 'Custom Apex Sharing Reasons Defined', severity: 'low' },
    { title: 'Custom Sharing Reasons Have No Corresponding Active Apex Class', severity: 'low' },
  ],
  'Record Teams': [
    { title: 'Account Team Roles Grant Edit Access — Review Least Privilege', severity: 'medium' },
    { title: 'Opportunity Team Roles Grant Edit Access — Review Least Privilege', severity: 'medium' },
    { title: 'Case Teams Active with Private Case OWD — Review Access Patterns', severity: 'medium' },
  ],
  'Groups & Queues': [
    { title: 'Public Groups Include All Internal Users', severity: 'high' },
    { title: 'Queues Have No Members — Work Items Cannot Be Assigned', severity: 'medium' },
    { title: 'Queues Have "Include Bosses" Enabled on Private OWD Objects', severity: 'medium' },
    { title: 'Nested Group Memberships Detected', severity: 'medium' },
    { title: 'Public Groups Have No Members', severity: 'low' },
    { title: 'Queues Configured on Public OWD Objects — Redundant Access Mechanism', severity: 'low' },
    { title: 'Nested Group Membership Detected (low volume)', severity: 'low' },
  ],
  'Permission Bypasses': [
    { title: 'Many Users Have View All Data — Complete Sharing Bypass (5+)', severity: 'critical' },
    { title: 'Many Users Have Modify All Data — Complete Sharing Bypass (5+)', severity: 'critical' },
    { title: 'Users Have View All Data — Complete Sharing Bypass', severity: 'high' },
    { title: 'Users Have Modify All Data — Complete Sharing Bypass', severity: 'high' },
    { title: 'View All Records Granted on Many Objects (10+)', severity: 'high' },
    { title: 'Modify All Records Granted on Many Objects (5+)', severity: 'high' },
    { title: 'High Percentage of Active Users Have Org-Wide Sharing Bypass Permissions', severity: 'high' },
    { title: 'Many Users Hold High-Risk Admin Permissions (Author Apex / Manage Users)', severity: 'high' },
    { title: 'Majority of Sharing Bypass Grants Are via Permission Sets — Harder to Audit', severity: 'medium' },
    { title: 'No Permission Set Groups Defined — Consider Adopting for Access Governance', severity: 'medium' },
    { title: 'Users Hold High-Risk Admin Permissions (Author Apex / Manage Users)', severity: 'medium' },
  ],
  'Implicit Sharing': [
    { title: 'Contact Visibility Controlled by Account — Implicit Sharing Active', severity: 'medium' },
    { title: 'Case Visibility Controlled by Account — Implicit Sharing Active', severity: 'medium' },
    { title: 'Account-Opportunity Implicit Sharing Is Active', severity: 'low' },
  ],
  'External & Guest Access': [
    { title: 'Objects Allow External Users to Create/Edit Records', severity: 'critical' },
    { title: 'Objects Are Accessible to External/Guest Users', severity: 'high' },
    { title: 'Sharing Sets Grant Access to High-Volume Portal Users', severity: 'medium' },
  ],
};

const TOTAL_CHECKS = Object.values(CATEGORY_CHECKS).reduce((sum, arr) => sum + arr.length, 0);

const GROUP_COLORS: Record<string, string> = {
  'Foundation':     '#0070d2',
  'Sharing':        '#8e44ad',
  'Access Control': '#d35400',
  'Visibility':     '#27ae60',
};

const CATEGORIES = [
  { icon: '🏠', name: 'OWD Analysis',            group: 'Foundation' },
  { icon: '🔼', name: 'Role Hierarchy',           group: 'Foundation' },
  { icon: '🗺️',  name: 'Territory Management',   group: 'Foundation' },
  { icon: '📋', name: 'Sharing Rules',            group: 'Sharing' },
  { icon: '✋', name: 'Manual Sharing',           group: 'Sharing' },
  { icon: '⚡', name: 'Apex Sharing',             group: 'Sharing' },
  { icon: '👥', name: 'Record Teams',             group: 'Access Control' },
  { icon: '🗂️',  name: 'Groups & Queues',        group: 'Access Control' },
  { icon: '🔑', name: 'Permission Bypasses',      group: 'Access Control' },
  { icon: '🔗', name: 'Implicit Sharing',         group: 'Visibility' },
  { icon: '🌐', name: 'External & Guest Access',  group: 'Visibility' },
];

const labelStyle: React.CSSProperties = {
  display: 'block',
  fontSize: '0.75rem',
  fontWeight: 600,
  color: '#5a6472',
  letterSpacing: '0.04em',
  marginBottom: '4px',
  textTransform: 'uppercase',
};

const inputStyle: React.CSSProperties = {
  display: 'block',
  width: '100%',
  padding: '10px 12px',
  border: '1px solid #d1d5db',
  borderRadius: '6px',
  fontSize: '0.88rem',
  color: '#1a2332',
  backgroundColor: 'white',
  outline: 'none',
  boxSizing: 'border-box',
  marginTop: '4px',
};

export const LoginPage: React.FC = () => {
  const [orgUrl, setOrgUrl] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [remember, setRemember] = useState(true);
  const [error, setError] = useState('');
  const [hoveredCategory, setHoveredCategory] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [showSetup, setShowSetup] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('error')) {
      setError(decodeURIComponent(params.get('error') || 'Authentication failed'));
    }
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const { orgUrl: u, clientId: c, clientSecret: s } = JSON.parse(saved);
        if (u) setOrgUrl(u);
        if (c) setClientId(c);
        if (s) setClientSecret(s);
      }
    } catch {} // ignore
    getAuthStatus().then(status => {
      if (status.authenticated) navigate('/dashboard');
    }).catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { setSelectedCategory(null); setShowSetup(false); }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, []);

  const handleConnect = (e: React.FormEvent) => {
    e.preventDefault();
    if (!clientId || !clientSecret) {
      setError('Consumer Key and Consumer Secret are required.');
      return;
    }
    if (remember) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ orgUrl, clientId, clientSecret }));
    }
    const url = `/auth/login?loginUrl=${encodeURIComponent(orgUrl)}&clientId=${encodeURIComponent(clientId)}&clientSecret=${encodeURIComponent(clientSecret)}`;
    window.location.href = url;
  };

  return (
    <div style={{
      display: 'flex',
      minHeight: '100vh',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    }}>
      {/* ── LEFT PANEL ── */}
      <div style={{
        flex: '0 0 60%',
        background: 'linear-gradient(145deg, #032D60 0%, #0070D2 60%, #1589EE 100%)',
        color: 'white',
        padding: '20px 40px',
        display: 'flex',
        flexDirection: 'column',
        overflowY: 'hidden',
      }}>
        {/* Header */}
        <div style={{ marginBottom: '10px' }}>
          <div style={{ marginBottom: '6px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 500, opacity: 0.85, letterSpacing: '0.05em' }}>
              SALESFORCE SHARING ANALYZER
            </span>
          </div>
          <h1 style={{
            fontSize: '1.8rem',
            fontWeight: 700,
            margin: '0 0 2px',
            lineHeight: 1.15,
            letterSpacing: '-0.02em',
          }}>
            Understand your org's sharing model in minutes.
          </h1>
          <p style={{ fontSize: '0.85rem', opacity: 0.75, margin: '0 0 4px', fontWeight: 400 }}>
            by <strong style={{ opacity: 1 }}>Steven Bilgram</strong>, Success Architect
          </p>
          <p style={{
            fontSize: '0.85rem',
            lineHeight: 1.5,
            opacity: 0.88,
            maxWidth: '520px',
            marginTop: '6px',
          }}>
            Connects securely to your Salesforce org via OAuth and runs a comprehensive
            read-only scan across <strong>{TOTAL_CHECKS} checks</strong> in {CATEGORIES.length} categories —
            mapping your complete sharing and visibility architecture with findings and remediation guidance.
          </p>
        </div>

        {/* Stats bar */}
        <div style={{
          display: 'flex',
          gap: '32px',
          marginBottom: '10px',
          paddingBottom: '10px',
          borderBottom: '1px solid rgba(255,255,255,0.2)',
        }}>
          {[
            { value: TOTAL_CHECKS, label: 'Total Checks' },
            { value: CATEGORIES.length, label: 'Categories' },
            { value: '100%', label: 'Read-Only' },
          ].map(stat => (
            <div key={stat.label}>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, lineHeight: 1 }}>{stat.value}</div>
              <div style={{ fontSize: '0.72rem', opacity: 0.7, marginTop: '3px', letterSpacing: '0.03em' }}>{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Category grid */}
        <div style={{ marginBottom: '6px' }}>
          <p style={{ fontSize: '0.72rem', opacity: 0.6, margin: '0 0 6px', letterSpacing: '0.03em' }}>
            Click any category to see all checks
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '7px' }}>
            {CATEGORIES.map(cat => {
              const accentColor = GROUP_COLORS[cat.group] || 'rgba(255,255,255,0.4)';
              const isHovered = hoveredCategory === cat.name;
              return (
                <div
                  key={cat.name}
                  onClick={() => setSelectedCategory(cat.name)}
                  onMouseEnter={() => setHoveredCategory(cat.name)}
                  onMouseLeave={() => setHoveredCategory(null)}
                  style={{
                    backgroundColor: isHovered ? 'rgba(255,255,255,0.2)' : 'rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    padding: '8px 10px',
                    backdropFilter: 'blur(4px)',
                    borderTop: isHovered ? '1px solid rgba(255,255,255,0.35)' : '1px solid rgba(255,255,255,0.12)',
                    borderRight: isHovered ? '1px solid rgba(255,255,255,0.35)' : '1px solid rgba(255,255,255,0.12)',
                    borderBottom: isHovered ? '1px solid rgba(255,255,255,0.35)' : '1px solid rgba(255,255,255,0.12)',
                    borderLeft: `3px solid ${accentColor}`,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    cursor: 'pointer',
                    transition: 'background-color 0.12s, border-color 0.12s',
                    userSelect: 'none',
                  }}
                >
                  <span style={{ fontSize: '1.1rem', flexShrink: 0 }}>{cat.icon}</span>
                  <div style={{ minWidth: 0 }}>
                    <div style={{
                      fontSize: '0.78rem',
                      fontWeight: 600,
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}>
                      {cat.name}
                    </div>
                    <div style={{ fontSize: '0.7rem', opacity: 0.65, marginTop: '1px' }}>
                      {(CATEGORY_CHECKS[cat.name] || []).length} check{(CATEGORY_CHECKS[cat.name] || []).length !== 1 ? 's' : ''}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Group legend */}
        <div style={{ marginTop: '4px', display: 'flex', flexWrap: 'wrap', gap: '5px 14px' }}>
          {Object.entries(GROUP_COLORS).map(([group, color]) => (
            <div key={group} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <div style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: color, flexShrink: 0 }} />
              <span style={{ fontSize: '0.68rem', opacity: 0.7, whiteSpace: 'nowrap' }}>{group}</span>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px solid rgba(255,255,255,0.15)' }}>
          <p style={{ margin: 0, fontSize: '0.72rem', color: 'rgba(255,255,255,0.75)', lineHeight: 1.5 }}>
            Read-only OAuth access · No data stored · Session only
          </p>
        </div>
      </div>

      {/* ── RIGHT PANEL ── */}
      <div style={{
        flex: '0 0 40%',
        backgroundColor: '#f8f9fa',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '48px 40px',
        overflowY: 'auto',
      }}>
        <div style={{ width: '100%', maxWidth: '380px' }}>

          {/* Disclaimer box */}
          <div style={{
            backgroundColor: '#eaf1fb',
            border: '1.5px solid #0070d2',
            borderRadius: '8px',
            padding: '14px 16px',
            marginBottom: '28px',
          }}>
            <p style={{ margin: '0 0 6px', fontSize: '0.82rem', fontWeight: 700, color: '#032d60', lineHeight: 1.4 }}>
              Important Disclaimer
            </p>
            <p style={{ margin: 0, fontSize: '0.80rem', color: '#032d60', lineHeight: 1.55 }}>
              SF Sharing Analyzer is provided "as is," without warranties. Its assessments and recommendations reflect my professional experience as a technical architect but are intended as decision-support guidance, not legal, regulatory, or financial advice.
            </p>
            <p style={{ margin: '8px 0 0', fontSize: '0.80rem', color: '#032d60', lineHeight: 1.55 }}>
              Users are responsible for validating results and adapting recommendations to their specific environment, requirements, and risks. I accept no liability for its use or misuse; by using the software, you accept these terms.
            </p>
          </div>

          <h2 style={{ fontSize: '1.4rem', fontWeight: 700, color: '#1a2332', margin: '0 0 6px' }}>
            Connect your org
          </h2>
          <p style={{ fontSize: '0.85rem', color: '#7f8c8d', margin: '0 0 32px', lineHeight: 1.5 }}>
            Enter your Connected App credentials to authenticate via Salesforce OAuth.
          </p>

          {error && (
            <div style={{
              backgroundColor: '#fdf0ed',
              border: '1px solid #e74c3c',
              borderRadius: '6px',
              padding: '10px 14px',
              marginBottom: '20px',
              fontSize: '0.82rem',
              color: '#c0392b',
            }}>
              {error}
            </div>
          )}

          <form onSubmit={handleConnect}>
            <div style={{ marginBottom: '16px' }}>
              <label style={labelStyle}>
                Org / Sandbox URL
                <input
                  type="text"
                  placeholder="https://company.my.salesforce.com"
                  value={orgUrl}
                  onChange={e => { setOrgUrl(e.target.value); setError(''); }}
                  style={inputStyle}
                />
              </label>
              <p style={{ fontSize: '0.72rem', color: '#aaa', margin: '4px 0 0' }}>
                Use your org's My Domain URL
              </p>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label style={labelStyle}>
                Client ID (Consumer Key)
                <input
                  type="text"
                  placeholder="3MVG9..."
                  value={clientId}
                  onChange={e => { setClientId(e.target.value); setError(''); }}
                  style={inputStyle}
                />
              </label>
            </div>

            <div style={{ marginBottom: '24px' }}>
              <label style={labelStyle}>
                Client Secret (Consumer Secret)
                <input
                  type="password"
                  placeholder="••••••••••••••••"
                  value={clientSecret}
                  onChange={e => { setClientSecret(e.target.value); setError(''); }}
                  style={inputStyle}
                />
              </label>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '24px' }}>
              <input
                type="checkbox"
                id="remember"
                checked={remember}
                onChange={e => setRemember(e.target.checked)}
                style={{ cursor: 'pointer', width: '15px', height: '15px', accentColor: '#0070D2' }}
              />
              <label htmlFor="remember" style={{ fontSize: '0.8rem', color: '#5a6472', cursor: 'pointer' }}>
                Remember credentials on this device
              </label>
            </div>

            <button
              type="submit"
              style={{
                background: 'linear-gradient(135deg, #0070D2 0%, #1589EE 100%)',
                color: 'white',
                border: 'none',
                padding: '14px 24px',
                borderRadius: '8px',
                fontSize: '0.95rem',
                fontWeight: 600,
                cursor: 'pointer',
                width: '100%',
                letterSpacing: '0.01em',
                boxShadow: '0 2px 8px rgba(0,112,210,0.35)',
                transition: 'opacity 0.15s, transform 0.1s',
              }}
              onMouseOver={e => { e.currentTarget.style.opacity = '0.92'; e.currentTarget.style.transform = 'translateY(-1px)'; }}
              onMouseOut={e => { e.currentTarget.style.opacity = '1'; e.currentTarget.style.transform = 'translateY(0)'; }}
            >
              Connect to Salesforce →
            </button>
          </form>

          <p style={{ marginTop: '20px', fontSize: '0.72rem', color: '#bdc3c7', lineHeight: 1.6, textAlign: 'center' }}>
            Need Instructions?{' '}
            <button
              onClick={() => setShowSetup(true)}
              style={{
                background: 'none',
                border: 'none',
                padding: 0,
                color: '#0070D2',
                fontWeight: 500,
                fontSize: '0.72rem',
                cursor: 'pointer',
              }}
            >
              See the setup guide →
            </button>
          </p>
        </div>
      </div>

      {/* ── CATEGORY MODAL ── */}
      {selectedCategory && (
        <div
          onClick={() => setSelectedCategory(null)}
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '24px',
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              backgroundColor: 'white',
              borderRadius: '12px',
              width: '100%',
              maxWidth: '520px',
              maxHeight: '75vh',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 20px 60px rgba(0,0,0,0.25)',
              overflow: 'hidden',
            }}
          >
            <div style={{
              padding: '18px 24px 14px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: 'linear-gradient(135deg, #032D60 0%, #0070D2 100%)',
              color: 'white',
              flexShrink: 0,
            }}>
              <div>
                <h3 style={{ margin: '0 0 2px', fontSize: '1rem', fontWeight: 700 }}>{selectedCategory}</h3>
                <p style={{ margin: 0, fontSize: '0.78rem', opacity: 0.75 }}>
                  {(CATEGORY_CHECKS[selectedCategory] || []).length} checks in this category
                </p>
              </div>
              <button
                onClick={() => setSelectedCategory(null)}
                style={{
                  background: 'rgba(255,255,255,0.2)',
                  border: 'none',
                  borderRadius: '50%',
                  width: '28px',
                  height: '28px',
                  fontSize: '1.1rem',
                  cursor: 'pointer',
                  color: 'white',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >×</button>
            </div>
            <div style={{ overflowY: 'auto', padding: '16px 24px 20px' }}>
              {(CATEGORY_CHECKS[selectedCategory] || []).map((check, i) => {
                const checks = CATEGORY_CHECKS[selectedCategory] || [];
                const dotColor = check.severity === 'critical' ? '#c0392b' : check.severity === 'high' ? '#d35400' : check.severity === 'medium' ? '#f39c12' : '#27ae60';
                const bgColor = check.severity === 'critical' ? '#fdf0ed' : check.severity === 'high' ? '#fef5e7' : check.severity === 'medium' ? '#fef9e7' : '#eafaf1';
                return (
                  <div key={i} style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                    padding: '6px 0',
                    borderBottom: i < checks.length - 1 ? '1px solid #f3f4f6' : 'none',
                  }}>
                    <span style={{
                      backgroundColor: bgColor,
                      color: dotColor,
                      fontSize: '0.65rem',
                      fontWeight: 700,
                      padding: '2px 6px',
                      borderRadius: '10px',
                      flexShrink: 0,
                      marginTop: '1px',
                      textTransform: 'uppercase',
                    }}>
                      {check.severity}
                    </span>
                    <span style={{ fontSize: '0.82rem', color: '#2c3e50', lineHeight: 1.4 }}>{check.title}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── SETUP GUIDE MODAL ── */}
      {showSetup && (
        <div
          onClick={() => setShowSetup(false)}
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '24px',
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              backgroundColor: 'white',
              borderRadius: '12px',
              width: '100%',
              maxWidth: '640px',
              maxHeight: '82vh',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 20px 60px rgba(0,0,0,0.25)',
              overflow: 'hidden',
            }}
          >
            <div style={{
              padding: '20px 24px 16px',
              borderBottom: '1px solid #f0f0f0',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'flex-start',
              flexShrink: 0,
              background: 'linear-gradient(135deg, #032D60 0%, #0070D2 100%)',
              color: 'white',
            }}>
              <div>
                <h3 style={{ margin: '0 0 4px', fontSize: '1.1rem', fontWeight: 700 }}>Setup Guide</h3>
                <p style={{ margin: 0, fontSize: '0.8rem', opacity: 0.75 }}>
                  Register the app once per Salesforce org you want to analyze
                </p>
              </div>
              <button
                onClick={() => setShowSetup(false)}
                style={{
                  background: 'rgba(255,255,255,0.2)',
                  border: 'none',
                  borderRadius: '50%',
                  width: '28px',
                  height: '28px',
                  fontSize: '1.1rem',
                  cursor: 'pointer',
                  color: 'white',
                  lineHeight: 1,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >×</button>
            </div>
            <div style={{ overflowY: 'auto', padding: '20px 24px 28px', fontSize: '0.875rem', color: '#2c3e50', lineHeight: 1.6 }}>
              <div style={{ backgroundColor: '#f0f7ff', borderRadius: '8px', padding: '14px 16px', marginBottom: '20px', border: '1px solid #cce0ff' }}>
                <p style={{ margin: '0 0 8px', fontWeight: 600, color: '#0070D2' }}>How to tell which setup your org uses</p>
                <p style={{ margin: '0 0 4px' }}>
                  <strong>External Client App</strong> — newer orgs (Spring '25+). Go to Setup and search for <strong>"External Client Apps"</strong>. If it appears, use Option A.
                </p>
                <p style={{ margin: 0 }}>
                  <strong>Connected App</strong> — older orgs. Go to Setup → <strong>App Manager</strong>. If you see a <strong>"New Connected App"</strong> button, use Option B.
                </p>
              </div>

              <h4 style={{ margin: '0 0 10px', fontSize: '0.9rem', color: '#032D60', borderBottom: '2px solid #0070D2', paddingBottom: '6px' }}>
                Option A — External Client App (newer orgs, Spring '25+)
              </h4>
              <ol style={{ margin: '0 0 20px', paddingLeft: '20px' }}>
                {([
                  <>Log in as Administrator → <strong>Setup → External Client Apps → New</strong></>,
                  <>Fill in: <strong>Label:</strong> SF Sharing Analyzer · <strong>API Name:</strong> SF_Sharing_Analyzer · <strong>Contact Email:</strong> your email</>,
                  <>Under <strong>OAuth Settings</strong>, check <strong>Enable OAuth</strong></>,
                  <>Set <strong>Callback URL</strong> to:<br />
                    <code style={{ display: 'inline-block', marginTop: '4px', padding: '4px 8px', backgroundColor: '#f4f4f4', borderRadius: '4px', fontSize: '0.8rem', color: '#c0392b', wordBreak: 'break-all' }}>
                      https://sf-sharing-analyzer-production.up.railway.app/auth/callback
                    </code>
                  </>,
                  <>Under <strong>OAuth Scopes</strong>, add: <em>Access and manage your data (api)</em> and <em>Perform requests on your behalf at any time (refresh_token, offline_access)</em></>,
                  <>Click <strong>Save</strong> — no wait time required</>,
                  <>Go back to the External Client App → <strong>View Consumer Details</strong> to retrieve your <strong>Consumer Key</strong> (Client ID) and <strong>Consumer Secret</strong></>,
                ] as React.ReactNode[]).map((step, i) => (
                  <li key={i} style={{ marginBottom: '8px' }}>{step}</li>
                ))}
              </ol>

              <h4 style={{ margin: '0 0 10px', fontSize: '0.9rem', color: '#032D60', borderBottom: '2px solid #16a34a', paddingBottom: '6px' }}>
                Option B — Connected App (all orgs)
              </h4>
              <ol style={{ margin: '0 0 20px', paddingLeft: '20px' }}>
                {([
                  <>Log in as Administrator → <strong>Setup → App Manager → New Connected App</strong></>,
                  <>Fill in App Name (e.g., <em>SF Sharing Analyzer</em>) and Contact Email</>,
                  <>Check <strong>Enable OAuth Settings</strong></>,
                  <>Set <strong>Callback URL</strong> to:<br />
                    <code style={{ display: 'inline-block', marginTop: '4px', padding: '4px 8px', backgroundColor: '#f4f4f4', borderRadius: '4px', fontSize: '0.8rem', color: '#c0392b', wordBreak: 'break-all' }}>
                      https://sf-sharing-analyzer-production.up.railway.app/auth/callback
                    </code>
                  </>,
                  <>Add OAuth Scopes: <em>Access and manage your data (api)</em> and <em>Perform requests at any time (refresh_token)</em></>,
                  <>Click <strong>Save</strong> — wait 2–10 minutes for Salesforce to activate the app</>,
                  <>Copy the <strong>Consumer Key</strong> and <strong>Consumer Secret</strong> into the form</>,
                ] as React.ReactNode[]).map((step, i) => (
                  <li key={i} style={{ marginBottom: '8px' }}>{step}</li>
                ))}
              </ol>

              <p style={{ fontSize: '0.82rem', color: '#9ca3af', margin: 0 }}>
                Read-only API access only. No data is stored — all results live in your browser session.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
