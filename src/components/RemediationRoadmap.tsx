import React from 'react';
import { AssessmentResult, SharingFinding } from '../types/assessment';

interface RemediationRoadmapProps {
  assessment: AssessmentResult;
  onClose: () => void;
}

export const RemediationRoadmap: React.FC<RemediationRoadmapProps> = ({ assessment, onClose }) => {
  const allFindings: SharingFinding[] = assessment.categories.flatMap(c => c.items);

  const critical = allFindings.filter(f => f.severity === 'critical');
  const high = allFindings.filter(f => f.severity === 'high');
  const medium = allFindings.filter(f => f.severity === 'medium');
  const low = allFindings.filter(f => f.severity === 'low');

  // Assign findings to phases by category priority
  const phase1Categories = ['Permission Bypasses', 'OWD Analysis', 'External & Guest Access'];
  const phase2Categories = ['Sharing Rules', 'Role Hierarchy', 'Apex Sharing', 'Territory Management'];
  const phase3Categories = ['Manual Sharing', 'Groups & Queues', 'Implicit Sharing', 'Record Teams'];

  const phase1Findings = allFindings.filter(f =>
    f.severity === 'critical' || (f.severity === 'high' && phase1Categories.includes(f.category))
  );
  const phase2Findings = allFindings.filter(f =>
    !phase1Findings.includes(f) && phase2Categories.includes(f.category)
  );
  const phase3Findings = allFindings.filter(f =>
    !phase1Findings.includes(f) && !phase2Findings.includes(f) &&
    (phase3Categories.includes(f.category) || f.severity === 'medium')
  );
  const phase4Findings = allFindings.filter(f =>
    !phase1Findings.includes(f) && !phase2Findings.includes(f) && !phase3Findings.includes(f)
  );

  const phases = [
    {
      number: 1,
      title: 'Critical & High Priority',
      timeline: 'Weeks 1–4',
      color: '#c0392b',
      focus: 'Fix permission bypasses (View All Data / Modify All Data), restrict any Public Read/Write OWD on sensitive objects, lock down external OWD settings.',
      findings: phase1Findings
    },
    {
      number: 2,
      title: 'Architecture Remediation',
      timeline: 'Weeks 5–12',
      color: '#d35400',
      focus: 'Consolidate and reduce sharing rules, restructure the role hierarchy, address Apex sharing issues, clean up territory configuration.',
      findings: phase2Findings
    },
    {
      number: 3,
      title: 'Optimization',
      timeline: 'Weeks 13–20',
      color: '#f39c12',
      focus: 'Replace manual sharing with systematic rules, clean up empty groups and queues, document and review implicit sharing chains, audit record team access levels.',
      findings: phase3Findings
    },
    {
      number: 4,
      title: 'Governance & Monitoring',
      timeline: 'Ongoing',
      color: '#27ae60',
      focus: 'Establish a sharing governance process with quarterly reviews, document the sharing architecture, set up monitoring for bypass permission grants, and train admins on sharing model best practices.',
      findings: phase4Findings
    }
  ];

  return (
    <div style={{
      position: 'fixed',
      top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(0,0,0,0.5)',
      zIndex: 1000,
      overflow: 'auto'
    }}>
      <div style={{
        backgroundColor: 'white',
        maxWidth: '900px',
        margin: '40px auto',
        borderRadius: '12px',
        padding: '40px',
        position: 'relative'
      }}>
        <button
          onClick={onClose}
          style={{
            position: 'absolute',
            top: '20px',
            right: '20px',
            background: 'none',
            border: 'none',
            fontSize: '1.5rem',
            cursor: 'pointer',
            color: '#7f8c8d'
          }}
        >
          ✕
        </button>

        <h2 style={{ margin: '0 0 8px', color: '#2c3e50' }}>Sharing Remediation Roadmap</h2>
        <p style={{ color: '#7f8c8d', marginBottom: '32px' }}>
          {assessment.orgName || 'Your Org'} — Overall Sharing Score: <strong>{assessment.overallScore}%</strong>
          {' · '}{critical.length} Critical · {high.length} High · {medium.length} Medium · {low.length} Low
        </p>

        {phases.map(phase => (
          <div key={phase.number} style={{
            marginBottom: '32px',
            border: `1px solid ${phase.color}`,
            borderLeft: `6px solid ${phase.color}`,
            borderRadius: '8px',
            padding: '20px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
              <div>
                <span style={{
                  backgroundColor: phase.color,
                  color: 'white',
                  padding: '2px 10px',
                  borderRadius: '12px',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  marginRight: '10px'
                }}>
                  Phase {phase.number}
                </span>
                <span style={{ fontWeight: 700, fontSize: '1rem', color: '#2c3e50' }}>{phase.title}</span>
              </div>
              <span style={{ color: '#7f8c8d', fontSize: '0.85rem', whiteSpace: 'nowrap' }}>{phase.timeline}</span>
            </div>
            <p style={{ margin: '0 0 12px', color: '#555', fontSize: '0.9rem' }}>{phase.focus}</p>

            {phase.findings.length > 0 ? (
              <div>
                <div style={{ fontSize: '0.8rem', color: '#7f8c8d', marginBottom: '6px' }}>
                  {phase.findings.length} finding{phase.findings.length > 1 ? 's' : ''} in this phase:
                </div>
                {phase.findings.map(f => (
                  <div key={f.id} style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    padding: '6px 0',
                    borderBottom: '1px solid rgba(0,0,0,0.05)',
                    fontSize: '0.85rem'
                  }}>
                    <span style={{
                      color: f.severity === 'critical' ? '#c0392b' : f.severity === 'high' ? '#d35400' : f.severity === 'medium' ? '#f39c12' : '#27ae60',
                      fontWeight: 700,
                      fontSize: '0.7rem',
                      textTransform: 'uppercase',
                      minWidth: '60px'
                    }}>
                      {f.severity}
                    </span>
                    <span style={{ color: '#2c3e50' }}>{f.title}</span>
                    <span style={{ color: '#aaa', fontSize: '0.75rem' }}>— {f.category}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ color: '#7f8c8d', fontSize: '0.85rem', fontStyle: 'italic', margin: 0 }}>
                No findings assigned to this phase.
              </p>
            )}
          </div>
        ))}

        <div style={{ textAlign: 'center', marginTop: '24px' }}>
          <button
            onClick={onClose}
            style={{
              backgroundColor: '#1a56db',
              color: 'white',
              border: 'none',
              padding: '12px 28px',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '0.9rem'
            }}
          >
            Close Roadmap
          </button>
        </div>
      </div>
    </div>
  );
};
