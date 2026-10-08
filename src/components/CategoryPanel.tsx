import React from 'react';
import { CategoryResult } from '../types/assessment';
import { FindingCard } from './FindingCard';

interface CategoryPanelProps {
  result: CategoryResult;
  selectedSeverity: string | null;
}

function scoreColor(score: number): string {
  if (score >= 80) return '#27ae60';
  if (score >= 60) return '#f39c12';
  if (score >= 40) return '#d35400';
  return '#c0392b';
}

export const CategoryPanel: React.FC<CategoryPanelProps> = ({ result, selectedSeverity }) => {
  const [expanded, setExpanded] = React.useState(false);
  const color = scoreColor(result.score);

  const filtered = selectedSeverity
    ? result.items.filter(i => i.severity === selectedSeverity)
    : result.items;

  const hasCritical = result.items.some(i => i.severity === 'critical');
  const hasHigh = result.items.some(i => i.severity === 'high');

  return (
    <div style={{
      border: '1px solid #e0e0e0',
      borderRadius: '10px',
      marginBottom: '16px',
      overflow: 'hidden',
      backgroundColor: 'white'
    }}>
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          padding: '16px 20px',
          cursor: 'pointer',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          backgroundColor: expanded ? '#f8f9fa' : 'white',
          borderBottom: expanded ? '1px solid #e0e0e0' : 'none'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '44px',
            height: '44px',
            borderRadius: '50%',
            backgroundColor: color,
            color: 'white',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontWeight: 700,
            fontSize: '0.85rem'
          }}>
            {result.score}
          </div>
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.95rem', color: '#2c3e50' }}>
              {result.category}
            </div>
            <div style={{ fontSize: '0.8rem', color: '#7f8c8d', marginTop: '2px' }}>
              {result.items.length === 0 ? 'No issues found' : `${result.items.length} finding${result.items.length > 1 ? 's' : ''}`}
              {hasCritical && <span style={{ marginLeft: '8px', color: '#c0392b', fontWeight: 600 }}>● Critical</span>}
              {!hasCritical && hasHigh && <span style={{ marginLeft: '8px', color: '#d35400', fontWeight: 600 }}>● High</span>}
            </div>
          </div>
        </div>
        <span style={{ color: '#7f8c8d', fontSize: '1.2rem' }}>{expanded ? '▲' : '▼'}</span>
      </div>

      {expanded && (
        <div style={{ padding: '16px 20px' }}>
          {filtered.length === 0 ? (
            <p style={{ color: '#7f8c8d', fontSize: '0.9rem', margin: 0 }}>
              {result.items.length === 0 ? 'No issues found in this category.' : 'No issues match the selected filter.'}
            </p>
          ) : (
            filtered.map(item => <FindingCard key={item.id} item={item} />)
          )}
        </div>
      )}
    </div>
  );
};
