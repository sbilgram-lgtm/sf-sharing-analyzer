import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { CategoryPanel } from '../components/CategoryPanel';
import { RemediationRoadmap } from '../components/RemediationRoadmap';
import {
  getAuthStatus, getOwdData, getRoleHierarchyData, getTerritoriesData,
  getSharingRulesData, getManualSharingData, getApexSharingData,
  getRecordTeamsData, getGroupsQueuesData, getPermissionBypassesData,
  getImplicitSharingData, getExternalAccessData
} from '../services/api';
import {
  assessOwd, assessRoleHierarchy, assessTerritories, assessSharingRules,
  assessManualSharing, assessApexSharing, assessRecordTeams,
  assessGroupsQueues, assessPermissionBypasses, assessImplicitSharing,
  assessExternalAccess, calculateOverallScore
} from '../utils/scoring';
import { AssessmentResult } from '../types/assessment';
import { generatePDFReport } from '../utils/reportGenerator';
type ActiveView = 'findings' | 'inventory';

function scoreColor(score: number): string {
  if (score >= 80) return '#27ae60';
  if (score >= 60) return '#f39c12';
  if (score >= 40) return '#d35400';
  return '#c0392b';
}

export const DashboardPage: React.FC = () => {
  const [assessment, setAssessment] = useState<AssessmentResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState('');
  const [showRoadmap, setShowRoadmap] = useState(false);
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<ActiveView>('findings');
  const navigate = useNavigate();

  useEffect(() => {
    getAuthStatus().then(status => {
      if (!status.authenticated) navigate('/login');
      else runAssessment();
    }).catch(() => navigate('/login'));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const runAssessment = async () => {
    setLoading(true);
    setError(null);

    try {
      setProgress('Analyzing OWD settings...');
      const owdData = await getOwdData();

      setProgress('Analyzing role hierarchy...');
      const roleData = await getRoleHierarchyData();

      setProgress('Checking territory management...');
      const territoryData = await getTerritoriesData();

      setProgress('Analyzing sharing rules...');
      const sharingRulesData = await getSharingRulesData();

      setProgress('Checking manual sharing volume...');
      const manualSharingData = await getManualSharingData();

      setProgress('Scanning Apex sharing...');
      const apexSharingData = await getApexSharingData();

      setProgress('Checking record teams...');
      const recordTeamsData = await getRecordTeamsData();

      setProgress('Auditing groups & queues...');
      const groupsQueuesData = await getGroupsQueuesData();

      setProgress('Auditing permission bypasses...');
      const bypassData = await getPermissionBypassesData();

      setProgress('Analyzing implicit sharing chains...');
      const implicitData = await getImplicitSharingData();

      setProgress('Checking external & guest access...');
      const externalData = await getExternalAccessData();

      setProgress('Calculating scores...');
      const owdEntities = owdData?.entities || [];
      const owdResult = assessOwd(owdData);
      const roleResult = assessRoleHierarchy(roleData);
      const territoryResult = assessTerritories(territoryData);
      const sharingRulesResult = assessSharingRules(sharingRulesData, owdEntities);
      const manualResult = assessManualSharing(manualSharingData, owdEntities);
      const apexResult = assessApexSharing(apexSharingData);
      const teamsResult = assessRecordTeams(recordTeamsData, owdEntities);
      const groupsResult = assessGroupsQueues(groupsQueuesData, owdEntities);
      const bypassResult = assessPermissionBypasses(bypassData);
      const implicitResult = assessImplicitSharing(implicitData);
      const externalResult = assessExternalAccess(externalData);

      const result = calculateOverallScore([
        owdResult, roleResult, territoryResult, sharingRulesResult,
        manualResult, apexResult, teamsResult, groupsResult,
        bypassResult, implicitResult, externalResult
      ]);

      const authStatus = await getAuthStatus();
      result.instanceUrl  = authStatus.instanceUrl;
      result.orgId        = authStatus.orgId;
      result.orgName      = authStatus.orgName;
      result.orgType      = authStatus.orgType;
      result.isSandbox    = authStatus.isSandbox;
      result.instanceName = authStatus.instanceName;

      // Attach inventory data
      result.owdInventory = owdResult.inventory || [];
      result.sharingRulesSummary = (sharingRulesResult as any).stats?.summary || [];
      result.roleStats = (roleResult as any).stats;
      result.teamStats = (teamsResult as any).stats;
      result.bypassStats = (bypassResult as any).stats;
      result.territoryStats = (territoryResult as any).stats;

      setAssessment(result);
    } catch (err: any) {
      setError(err.message || 'Assessment failed');
    } finally {
      setLoading(false);
      setProgress('');
    }
  };

  const getSeverityCount = (sev: string) =>
    assessment?.categories.flatMap(c => c.items).filter(i => i.severity === sev).length || 0;

  return (
    <div style={{ padding: '32px', maxWidth: '1200px', margin: '0 auto' }}>

      {loading && (
        <div style={{ textAlign: 'center', padding: '60px 0' }}>
          <div style={{
            width: '48px', height: '48px',
            border: '4px solid #ecf0f1',
            borderTop: '4px solid #1a56db',
            borderRadius: '50%',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 20px'
          }} />
          <p style={{ color: '#7f8c8d', fontSize: '1rem' }}>{progress}</p>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      )}

      {error && (
        <div style={{
          backgroundColor: '#fdf0ed',
          border: '1px solid #c0392b',
          borderRadius: '8px',
          padding: '16px',
          marginBottom: '24px',
          color: '#c0392b'
        }}>
          <strong>Error:</strong> {error}
          <button
            onClick={runAssessment}
            style={{ marginLeft: '16px', cursor: 'pointer', textDecoration: 'underline', background: 'none', border: 'none', color: '#c0392b' }}
          >
            Retry
          </button>
        </div>
      )}

      {assessment && (
        <>
          {/* Header row */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <h2 style={{ margin: 0, color: '#1a1a2e' }}>Sharing Architecture Review</h2>
              {assessment.orgName && (
                <p style={{ margin: '4px 0 0', color: '#7f8c8d', fontSize: '0.9rem' }}>
                  {assessment.orgName}
                  {assessment.isSandbox && <span style={{ marginLeft: '8px', backgroundColor: '#f39c12', color: 'white', padding: '1px 6px', borderRadius: '10px', fontSize: '0.75rem' }}>Sandbox</span>}
                </p>
              )}
            </div>
            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
              <button onClick={runAssessment} style={{ backgroundColor: 'white', border: '1px solid #1a56db', color: '#1a56db', padding: '9px 18px', borderRadius: '6px', cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600 }}>
                Re-run Analysis
              </button>
              <button onClick={() => assessment && generatePDFReport(assessment)} style={{ backgroundColor: '#1a56db', color: 'white', border: 'none', padding: '9px 18px', borderRadius: '6px', cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600 }}>
                Export PDF
              </button>
              <button onClick={() => setShowRoadmap(true)} style={{ backgroundColor: '#27ae60', color: 'white', border: 'none', padding: '9px 18px', borderRadius: '6px', cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600 }}>
                Remediation Roadmap
              </button>
            </div>
          </div>

          {/* Score overview */}
          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '24px', marginBottom: '32px', backgroundColor: 'white', borderRadius: '12px', padding: '24px', boxShadow: '0 1px 6px rgba(0,0,0,0.06)' }}>
            <div style={{ textAlign: 'center', minWidth: '120px' }}>
              <div style={{ fontSize: '3.5rem', fontWeight: 800, color: scoreColor(assessment.overallScore), lineHeight: 1 }}>
                {assessment.overallScore}
              </div>
              <div style={{ fontSize: '0.8rem', color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: '4px' }}>
                Overall Score
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
              {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
                const count = getSeverityCount(sev);
                const colors: Record<string, { bg: string; text: string }> = {
                  critical: { bg: '#fdf0ed', text: '#c0392b' },
                  high:     { bg: '#fef5e7', text: '#d35400' },
                  medium:   { bg: '#fef9e7', text: '#f39c12' },
                  low:      { bg: '#eafaf1', text: '#27ae60' }
                };
                return (
                  <div
                    key={sev}
                    onClick={() => setSelectedSeverity(selectedSeverity === sev ? null : sev)}
                    style={{
                      backgroundColor: selectedSeverity === sev ? colors[sev].text : colors[sev].bg,
                      color: selectedSeverity === sev ? 'white' : colors[sev].text,
                      padding: '10px 16px',
                      borderRadius: '8px',
                      cursor: 'pointer',
                      textAlign: 'center',
                      minWidth: '80px',
                      transition: 'all 0.15s'
                    }}
                  >
                    <div style={{ fontSize: '1.6rem', fontWeight: 800, lineHeight: 1 }}>{count}</div>
                    <div style={{ fontSize: '0.7rem', textTransform: 'uppercase', fontWeight: 600, marginTop: '2px' }}>{sev}</div>
                  </div>
                );
              })}
              {selectedSeverity && (
                <button
                  onClick={() => setSelectedSeverity(null)}
                  style={{ background: 'none', border: '1px solid #d1d5db', borderRadius: '6px', padding: '6px 12px', cursor: 'pointer', color: '#6b7280', fontSize: '0.8rem' }}
                >
                  Clear filter
                </button>
              )}
            </div>
          </div>

          {/* View tabs */}
          <div style={{ display: 'flex', gap: '0', marginBottom: '24px', borderBottom: '2px solid #e5e7eb' }}>
            {(['findings', 'inventory'] as const).map(view => (
              <button
                key={view}
                onClick={() => setActiveView(view)}
                style={{
                  padding: '10px 24px',
                  border: 'none',
                  background: 'none',
                  cursor: 'pointer',
                  fontSize: '0.9rem',
                  fontWeight: 600,
                  color: activeView === view ? '#1a56db' : '#6b7280',
                  borderBottom: activeView === view ? '2px solid #1a56db' : '2px solid transparent',
                  marginBottom: '-2px'
                }}
              >
                {view === 'findings' ? 'Findings' : 'Current State Inventory'}
              </button>
            ))}
          </div>

          {/* Findings view */}
          {activeView === 'findings' && (
            <div>
              {assessment.categories.map(cat => (
                <CategoryPanel key={cat.category} result={cat} selectedSeverity={selectedSeverity} />
              ))}
            </div>
          )}

          {/* Current State Inventory view */}
          {activeView === 'inventory' && (
            <InventoryView assessment={assessment} />
          )}
        </>
      )}

      {showRoadmap && assessment && (
        <RemediationRoadmap assessment={assessment} onClose={() => setShowRoadmap(false)} />
      )}
    </div>
  );
};

// ── Inventory View Component ──────────────────────────────────────────────────
function InventoryView({ assessment }: { assessment: AssessmentResult }) {
  const owdEntities: any[] = (assessment.owdInventory as any[]) || [];
  const sharingRulesSummary: any[] = (assessment.sharingRulesSummary as any[]) || [];
  const roleStats = assessment.roleStats;
  const teamStats = assessment.teamStats;
  const bypassStats = assessment.bypassStats;
  const territoryStats = assessment.territoryStats;

  function owdColor(model: string): string {
    if (model === 'Private') return '#27ae60';
    if (model === 'Read') return '#f39c12';
    if (model === 'ReadWrite') return '#c0392b';
    if (model === 'ControlledByParent') return '#1a56db';
    return '#9ca3af';
  }

  const tableStyle: React.CSSProperties = { width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' };
  const thStyle: React.CSSProperties = { textAlign: 'left', padding: '8px 12px', borderBottom: '2px solid #e5e7eb', color: '#6b7280', fontWeight: 600, fontSize: '0.75rem', textTransform: 'uppercase' };
  const tdStyle: React.CSSProperties = { padding: '7px 12px', borderBottom: '1px solid #f3f4f6' };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>

      {/* Stats cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '16px' }}>
        {[
          { label: 'Total Objects', value: owdEntities.length, icon: '📦' },
          { label: 'Total Sharing Rules', value: (sharingRulesSummary.reduce((s, r) => s + r.ownerRules + r.criteriaRules, 0)), icon: '📋' },
          { label: 'Total Roles', value: roleStats?.totalRoles ?? '—', icon: '👥' },
          { label: 'View All Data Users', value: bypassStats?.vadCount ?? '—', icon: '⚠️' },
        ].map(s => (
          <div key={s.label} style={{ backgroundColor: 'white', borderRadius: '10px', padding: '16px', boxShadow: '0 1px 4px rgba(0,0,0,0.06)', textAlign: 'center' }}>
            <div style={{ fontSize: '1.5rem', marginBottom: '6px' }}>{s.icon}</div>
            <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#1a1a2e' }}>{s.value}</div>
            <div style={{ fontSize: '0.75rem', color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.04em' }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* OWD Table */}
      <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '24px', boxShadow: '0 1px 6px rgba(0,0,0,0.06)' }}>
        <h3 style={{ margin: '0 0 16px', color: '#1a1a2e', fontSize: '1rem' }}>Organization-Wide Defaults (OWD)</h3>
        {owdEntities.length === 0 ? (
          <p style={{ color: '#9ca3af' }}>No OWD data available.</p>
        ) : (
          <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
            <table style={tableStyle}>
              <thead>
                <tr>
                  <th style={thStyle}>Object</th>
                  <th style={thStyle}>Internal OWD</th>
                  <th style={thStyle}>External OWD</th>
                </tr>
              </thead>
              <tbody>
                {owdEntities.map((e: any, i: number) => (
                  <tr key={i} style={{ backgroundColor: i % 2 === 0 ? 'white' : '#fafafa' }}>
                    <td style={tdStyle}>{e.Label || e.QualifiedApiName}</td>
                    <td style={tdStyle}>
                      <span style={{ color: owdColor(e.InternalSharingModel), fontWeight: 500 }}>
                        {e.InternalSharingModel || '—'}
                      </span>
                    </td>
                    <td style={tdStyle}>
                      <span style={{ color: owdColor(e.ExternalSharingModel), fontWeight: 500 }}>
                        {e.ExternalSharingModel || '—'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Sharing Rules Summary */}
      {sharingRulesSummary.length > 0 && (
        <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '24px', boxShadow: '0 1px 6px rgba(0,0,0,0.06)' }}>
          <h3 style={{ margin: '0 0 16px', color: '#1a1a2e', fontSize: '1rem' }}>Sharing Rules by Object</h3>
          <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
            <table style={tableStyle}>
              <thead>
                <tr>
                  <th style={thStyle}>Object</th>
                  <th style={thStyle}>Owner-Based</th>
                  <th style={thStyle}>Criteria-Based</th>
                  <th style={thStyle}>Total</th>
                </tr>
              </thead>
              <tbody>
                {sharingRulesSummary.map((r: any, i: number) => (
                  <tr key={i} style={{ backgroundColor: i % 2 === 0 ? 'white' : '#fafafa' }}>
                    <td style={tdStyle}>{r.object}</td>
                    <td style={tdStyle}>{r.ownerRules}</td>
                    <td style={tdStyle}>{r.criteriaRules}</td>
                    <td style={{ ...tdStyle, fontWeight: 600 }}>{r.ownerRules + r.criteriaRules}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sidebar stats: Role Hierarchy, Teams, Bypasses, Territory */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>

        {roleStats && (
          <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '24px', boxShadow: '0 1px 6px rgba(0,0,0,0.06)' }}>
            <h3 style={{ margin: '0 0 16px', color: '#1a1a2e', fontSize: '1rem' }}>Role Hierarchy</h3>
            {[
              { label: 'Total Roles', value: roleStats.totalRoles },
              { label: 'Max Depth (levels)', value: roleStats.maxDepth },
              { label: 'Max Breadth (roles at one level)', value: roleStats.maxBreadth },
            ].map(s => (
              <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #f3f4f6', fontSize: '0.85rem' }}>
                <span style={{ color: '#6b7280' }}>{s.label}</span>
                <span style={{ fontWeight: 600, color: '#1a1a2e' }}>{s.value}</span>
              </div>
            ))}
          </div>
        )}

        {teamStats && (
          <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '24px', boxShadow: '0 1px 6px rgba(0,0,0,0.06)' }}>
            <h3 style={{ margin: '0 0 16px', color: '#1a1a2e', fontSize: '1rem' }}>Record Teams</h3>
            {[
              { label: 'Account Teams', value: teamStats.accountTeamEnabled ? `Enabled (${teamStats.accountTeamCount} members)` : 'Not in use' },
              { label: 'Case Teams', value: teamStats.caseTeamEnabled ? `Enabled (${teamStats.caseTeamCount} templates)` : 'Not in use' },
              { label: 'Opportunity Teams', value: teamStats.oppTeamEnabled ? `Enabled (${teamStats.oppTeamCount} members)` : 'Not in use' },
            ].map(s => (
              <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #f3f4f6', fontSize: '0.85rem' }}>
                <span style={{ color: '#6b7280' }}>{s.label}</span>
                <span style={{ fontWeight: 600, color: '#1a1a2e' }}>{s.value}</span>
              </div>
            ))}
          </div>
        )}

        {bypassStats && (
          <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '24px', boxShadow: '0 1px 6px rgba(0,0,0,0.06)' }}>
            <h3 style={{ margin: '0 0 16px', color: '#1a1a2e', fontSize: '1rem' }}>Permission Bypasses</h3>
            {[
              { label: 'Users with View All Data', value: bypassStats.vadCount, warn: bypassStats.vadCount > 0 },
              { label: 'Users with Modify All Data', value: bypassStats.madCount, warn: bypassStats.madCount > 0 },
              { label: 'Objects with View All Records', value: bypassStats.viewAllObjectCount },
              { label: 'Objects with Modify All Records', value: bypassStats.modifyAllObjectCount },
            ].map(s => (
              <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #f3f4f6', fontSize: '0.85rem' }}>
                <span style={{ color: '#6b7280' }}>{s.label}</span>
                <span style={{ fontWeight: 600, color: (s as any).warn ? '#c0392b' : '#1a1a2e' }}>{s.value}</span>
              </div>
            ))}
          </div>
        )}

        {territoryStats && (
          <div style={{ backgroundColor: 'white', borderRadius: '12px', padding: '24px', boxShadow: '0 1px 6px rgba(0,0,0,0.06)' }}>
            <h3 style={{ margin: '0 0 16px', color: '#1a1a2e', fontSize: '1rem' }}>Territory Management 2.0</h3>
            {!territoryStats.enabled ? (
              <p style={{ color: '#9ca3af', fontSize: '0.85rem', margin: 0 }}>Territory Management 2.0 is not enabled in this org.</p>
            ) : (
              [
                { label: 'Status', value: 'Enabled' },
                { label: 'Total Models', value: territoryStats.modelCount },
                { label: 'Total Territories', value: territoryStats.territoryCount },
              ].map(s => (
                <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #f3f4f6', fontSize: '0.85rem' }}>
                  <span style={{ color: '#6b7280' }}>{s.label}</span>
                  <span style={{ fontWeight: 600, color: '#1a1a2e' }}>{s.value}</span>
                </div>
              ))
            )}
          </div>
        )}
      </div>

    </div>
  );
}
