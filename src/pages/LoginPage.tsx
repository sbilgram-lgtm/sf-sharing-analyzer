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
  ],
  'Sharing Rules': [
    { title: 'Sharing Rules Target All Internal Users', severity: 'high' },
    { title: 'Total Sharing Rules — Recalculation Risk (500+)', severity: 'high' },
    { title: 'Total Sharing Rules — Review for Redundancy (200+)', severity: 'medium' },
    { title: 'Object Has High Number of Sharing Rules (50+)', severity: 'medium' },
  ],
  'Manual Sharing': [
    { title: 'Object Has Very High Manual Share Volume (10,000+)', severity: 'high' },
    { title: 'Object Has High Manual Share Volume (1,000+)', severity: 'medium' },
  ],
  'Apex Sharing': [
    { title: 'Many Apex Classes Run Without Sharing Enforcement (20+)', severity: 'high' },
    { title: 'Apex Classes Run Without Sharing Enforcement (5+)', severity: 'medium' },
    { title: 'Custom Apex Sharing Reasons Defined', severity: 'low' },
  ],
  'Record Teams': [
    { title: 'Account Team Roles Grant Edit Access — Review Least Privilege', severity: 'medium' },
    { title: 'Opportunity Team Roles Grant Edit Access — Review Least Privilege', severity: 'medium' },
  ],
  'Groups & Queues': [
    { title: 'Public Groups Include All Internal Users', severity: 'high' },
    { title: 'Public Groups Have No Members', severity: 'low' },
    { title: 'Queues Have No Members — Work Items Cannot Be Assigned', severity: 'medium' },
  ],
  'Permission Bypasses': [
    { title: 'Many Users Have View All Data — Complete Sharing Bypass (5+)', severity: 'critical' },
    { title: 'Users Have View All Data — Complete Sharing Bypass', severity: 'high' },
    { title: 'Many Users Have Modify All Data — Complete Sharing Bypass (5+)', severity: 'critical' },
    { title: 'Users Have Modify All Data — Complete Sharing Bypass', severity: 'high' },
    { title: 'View All Records Granted on Many Objects (10+)', severity: 'high' },
    { title: 'Modify All Records Granted on Many Objects (5+)', severity: 'high' },
  ],
  'Implicit Sharing': [
    { title: 'Contact Visibility Controlled by Account — Implicit Sharing Active', severity: 'medium' },
    { title: 'Case Visibility Controlled by Account — Implicit Sharing Active', severity: 'medium' },
    { title: 'Account-Opportunity Implicit Sharing Is Active', severity: 'low' },
  ],
  'External & Guest Access': [
    { title: 'Objects Allow External Users to Create/Edit Records', severity: 'critical' },
    { title: 'Objects Are Accessible to External/Guest Users', severity: 'high' },
  ],
};

const TOTAL_CHECKS = Object.values(CATEGORY_CHECKS).reduce((sum, arr) => sum + arr.length, 0);

export const LoginPage: React.FC = () => {
  const [orgUrl, setOrgUrl] = useState('https://login.salesforce.com');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [showSetup, setShowSetup] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) {
      try {
        const { orgUrl: u, clientId: c, clientSecret: s } = JSON.parse(saved);
        if (u) setOrgUrl(u);
        if (c) setClientId(c);
        if (s) setClientSecret(s);
      } catch (_) { /* ignore */ }
    }
    const params = new URLSearchParams(window.location.search);
    if (params.get('error')) {
      setError(decodeURIComponent(params.get('error') || 'Authentication failed'));
    }
    getAuthStatus().then(status => {
      if (status.authenticated) navigate('/dashboard');
    }).catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleConnect = (e: React.FormEvent) => {
    e.preventDefault();
    if (!clientId || !clientSecret) {
      setError('Consumer Key and Consumer Secret are required.');
      return;
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ orgUrl, clientId, clientSecret }));
    const url = `/auth/login?loginUrl=${encodeURIComponent(orgUrl)}&clientId=${encodeURIComponent(clientId)}&clientSecret=${encodeURIComponent(clientSecret)}`;
    window.location.href = url;
  };

  const severityCounts = Object.values(CATEGORY_CHECKS).flat().reduce((acc, c) => {
    acc[c.severity] = (acc[c.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#f0f4ff', display: 'flex', alignItems: 'flex-start', justifyContent: 'center', padding: '40px 16px' }}>
      <div style={{ width: '100%', maxWidth: '880px' }}>

        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '36px' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '64px',
            height: '64px',
            backgroundColor: '#1a56db',
            borderRadius: '16px',
            marginBottom: '16px'
          }}>
            <span style={{ color: 'white', fontSize: '28px' }}>🔒</span>
          </div>
          <h1 style={{ margin: '0 0 8px', fontSize: '2rem', color: '#1a1a2e', fontWeight: 800 }}>
            SF Sharing Analyzer
          </h1>
          <p style={{ color: '#6b7280', margin: 0, fontSize: '1.05rem' }}>
            Comprehensive Sharing &amp; Visibility Architecture Review
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '24px', marginTop: '16px', flexWrap: 'wrap' }}>
            {[
              { value: `${TOTAL_CHECKS}`, label: 'Checks' },
              { value: '11', label: 'Categories' },
              { value: '100%', label: 'Read-Only' },
              { value: '< 3 min', label: 'To Complete' }
            ].map(s => (
              <div key={s.label} style={{ textAlign: 'center' }}>
                <div style={{ fontWeight: 800, fontSize: '1.4rem', color: '#1a56db' }}>{s.value}</div>
                <div style={{ fontSize: '0.75rem', color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{s.label}</div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>

          {/* Connect form */}
          <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '28px', boxShadow: '0 1px 6px rgba(0,0,0,0.08)' }}>
            <h2 style={{ margin: '0 0 20px', fontSize: '1.1rem', color: '#1a1a2e' }}>Connect to Salesforce</h2>

            {error && (
              <div style={{ backgroundColor: '#fdf0ed', border: '1px solid #c0392b', borderRadius: '6px', padding: '10px 14px', marginBottom: '16px', color: '#c0392b', fontSize: '0.85rem' }}>
                {error}
              </div>
            )}

            <form onSubmit={handleConnect}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '6px', color: '#374151' }}>
                  Salesforce Login URL
                </label>
                <input
                  type="text"
                  value={orgUrl}
                  onChange={e => setOrgUrl(e.target.value)}
                  style={{ width: '100%', padding: '9px 12px', border: '1px solid #d1d5db', borderRadius: '6px', fontSize: '0.9rem', boxSizing: 'border-box' }}
                />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '6px', color: '#374151' }}>
                  Consumer Key
                </label>
                <input
                  type="text"
                  value={clientId}
                  onChange={e => setClientId(e.target.value)}
                  placeholder="3MVG9..."
                  style={{ width: '100%', padding: '9px 12px', border: '1px solid #d1d5db', borderRadius: '6px', fontSize: '0.9rem', boxSizing: 'border-box' }}
                />
              </div>
              <div style={{ marginBottom: '20px' }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 600, marginBottom: '6px', color: '#374151' }}>
                  Consumer Secret
                </label>
                <input
                  type="password"
                  value={clientSecret}
                  onChange={e => setClientSecret(e.target.value)}
                  style={{ width: '100%', padding: '9px 12px', border: '1px solid #d1d5db', borderRadius: '6px', fontSize: '0.9rem', boxSizing: 'border-box' }}
                />
              </div>
              <button
                type="submit"
                style={{
                  width: '100%',
                  backgroundColor: '#1a56db',
                  color: 'white',
                  border: 'none',
                  padding: '11px',
                  borderRadius: '7px',
                  fontSize: '0.95rem',
                  fontWeight: 600,
                  cursor: 'pointer'
                }}
              >
                Connect to Salesforce →
              </button>
            </form>

            <button
              type="button"
              onClick={() => navigate('/dashboard', { state: { demo: true } })}
              style={{
                width: '100%',
                background: 'transparent',
                border: '1px solid #d1d5db',
                color: '#6b7280',
                padding: '10px',
                borderRadius: '7px',
                fontSize: '0.85rem',
                cursor: 'pointer',
                marginTop: '10px',
              }}
            >
              View Demo Dashboard
            </button>

            <div style={{ marginTop: '12px', fontSize: '0.8rem', color: '#9ca3af', textAlign: 'center' }}>
              Read-only OAuth 2.0 · No data stored · Session only
            </div>
          </div>

          {/* Setup instructions */}
          <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '28px', boxShadow: '0 1px 6px rgba(0,0,0,0.08)' }}>
            <h2 style={{ margin: '0 0 20px', fontSize: '1.1rem', color: '#1a1a2e' }}>What's Covered</h2>

            <div style={{ marginBottom: '16px' }}>
              {Object.entries(CATEGORY_CHECKS).map(([cat, checks]) => (
                <div key={cat} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', borderBottom: '1px solid #f3f4f6', fontSize: '0.85rem' }}>
                  <span style={{ color: '#374151' }}>{cat}</span>
                  <span style={{ color: '#6b7280', fontWeight: 500 }}>{checks.length} checks</span>
                </div>
              ))}
            </div>

            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
                <span key={sev} style={{
                  padding: '3px 10px',
                  borderRadius: '12px',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  backgroundColor: sev === 'critical' ? '#fdf0ed' : sev === 'high' ? '#fef5e7' : sev === 'medium' ? '#fef9e7' : '#eafaf1',
                  color: sev === 'critical' ? '#c0392b' : sev === 'high' ? '#d35400' : sev === 'medium' ? '#f39c12' : '#27ae60'
                }}>
                  {severityCounts[sev] || 0} {sev}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Setup instructions accordion */}
        <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '0', marginTop: '24px', boxShadow: '0 1px 6px rgba(0,0,0,0.08)', overflow: 'hidden' }}>
          <button
            onClick={() => setShowSetup(!showSetup)}
            style={{
              width: '100%',
              padding: '18px 28px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              fontSize: '1rem',
              fontWeight: 600,
              color: '#1a1a2e',
              textAlign: 'left' as const
            }}
          >
            <span>How to Set Up Your Connected App</span>
            <span style={{ color: '#9ca3af' }}>{showSetup ? '▲' : '▼'}</span>
          </button>
          {showSetup && (
            <div style={{ padding: '0 28px 24px', borderTop: '1px solid #f3f4f6' }}>
              <ol style={{ paddingLeft: '20px', margin: '16px 0', lineHeight: '2' }}>
                <li>In Salesforce Setup, search for <strong>App Manager</strong> and click <strong>New Connected App</strong></li>
                <li>Fill in App Name (e.g., <em>SF Sharing Analyzer</em>), Contact Email</li>
                <li>Check <strong>Enable OAuth Settings</strong></li>
                <li>Set Callback URL to your app URL + <code>/auth/callback</code></li>
                <li>Add OAuth Scopes: <strong>Access and manage your data (api)</strong> and <strong>Perform requests at any time (refresh_token)</strong></li>
                <li>Save, wait 2–10 minutes for the app to activate</li>
                <li>Copy the <strong>Consumer Key</strong> and <strong>Consumer Secret</strong> into the form above</li>
              </ol>
              <p style={{ fontSize: '0.85rem', color: '#9ca3af', margin: 0 }}>
                The analyzer only requires read-only API access. No data is stored — all results live in your browser session.
              </p>
            </div>
          )}
        </div>

      </div>
    </div>
  );
};
