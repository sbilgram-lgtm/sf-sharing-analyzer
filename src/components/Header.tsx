import React from 'react';
import { useNavigate } from 'react-router-dom';
import { logout } from '../services/api';

interface HeaderProps {
  authenticated: boolean;
  instanceUrl?: string | null;
}

export const Header: React.FC<HeaderProps> = ({ authenticated, instanceUrl }) => {
  const navigate = useNavigate();

  const handleLogout = async () => {
    try { await logout(); } catch (_) { /* ignore */ }
    navigate('/login');
  };

  return (
    <div style={{
      backgroundColor: '#1a56db',
      color: 'white',
      padding: '12px 32px',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    }}>
      <div>
        <span style={{ fontWeight: 700, fontSize: '1rem' }}>SF Sharing Analyzer</span>
        {instanceUrl && (
          <span style={{ marginLeft: '16px', fontSize: '0.8rem', opacity: 0.8 }}>{instanceUrl}</span>
        )}
      </div>
      {authenticated && (
        <button
          onClick={handleLogout}
          style={{
            backgroundColor: 'rgba(255,255,255,0.15)',
            color: 'white',
            border: '1px solid rgba(255,255,255,0.4)',
            padding: '6px 14px',
            borderRadius: '5px',
            cursor: 'pointer',
            fontSize: '0.85rem'
          }}
        >
          Disconnect
        </button>
      )}
    </div>
  );
};
