import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, ArrowRight, Lock, Server, Activity } from 'lucide-react';
import { motion } from 'framer-motion';

const LandingPage = () => {
  const [domain, setDomain] = useState('');
  const [trustCenterUrl, setTrustCenterUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleScan = async (e) => {
    e.preventDefault();
    if (!domain) {
      setError('Domain is required');
      return;
    }

    setIsScanning(true);
    setError('');

    try {
      const response = await fetch('http://127.0.0.1:8000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain: domain,
          trust_center_url: trustCenterUrl || null
        })
      });

      const data = await response.json();

      if (!response.ok || data.error) {
        if (data.candidates && data.candidates.length > 0) {
          setError(`Could not auto-detect Trust Center. Try one of: ${data.candidates.join(', ')}`);
        } else {
          setError(data.error || data.detail || 'An error occurred during the scan.');
        }
      } else {
        navigate('/dashboard', { state: { scanResult: data } });
      }
    } catch (err) {
      console.error(err);
      setError('Failed to connect to the analysis engine. Is the backend running?');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', padding: '2rem' }}>
      
      <motion.div 
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        style={{ textAlign: 'center', marginBottom: '3rem' }}
      >
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '1.5rem' }}>
          <div style={{ padding: '1rem', background: 'var(--primary-light)', borderRadius: '50%' }}>
            <Shield size={48} color="var(--primary)" />
          </div>
        </div>
        <h1 style={{ fontSize: '3rem', marginBottom: '1rem', letterSpacing: '-1px' }}>
          NIST Posture <span style={{ color: 'var(--primary)' }}>Intelligence</span>
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '1.1rem', maxWidth: '600px', margin: '0 auto' }}>
          Automated OSINT-based security posture assessment engine targeting financial companies. 
          Powered by heuristic detection and local LLM extraction.
        </p>
      </motion.div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.2 }}
        className="glass-panel"
        style={{ width: '100%', maxWidth: '500px', padding: '2.5rem' }}
      >
        <form onSubmit={handleScan} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <label style={{ fontSize: '0.9rem', fontWeight: 500, color: 'var(--text-secondary)' }}>Target Domain *</label>
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <Server size={18} style={{ position: 'absolute', left: '16px', color: 'var(--text-muted)' }} />
              <input 
                type="text" 
                className="glass-input" 
                style={{ width: '100%', paddingLeft: '44px' }}
                placeholder="e.g., stripe.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                disabled={isScanning}
              />
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <label style={{ fontSize: '0.9rem', fontWeight: 500, color: 'var(--text-secondary)' }}>Trust Center URL (Optional)</label>
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <Lock size={18} style={{ position: 'absolute', left: '16px', color: 'var(--text-muted)' }} />
              <input 
                type="text" 
                className="glass-input" 
                style={{ width: '100%', paddingLeft: '44px' }}
                placeholder="Auto-detect if left blank"
                value={trustCenterUrl}
                onChange={(e) => setTrustCenterUrl(e.target.value)}
                disabled={isScanning}
              />
            </div>
          </div>

          {error && (
            <div style={{ padding: '1rem', background: 'var(--danger-light)', color: 'var(--danger)', borderRadius: 'var(--radius-sm)', fontSize: '0.9rem' }}>
              {error}
            </div>
          )}

          <button 
            type="submit" 
            className="btn-primary" 
            disabled={isScanning}
            style={{ marginTop: '0.5rem', width: '100%' }}
          >
            {isScanning ? (
              <>
                <Activity size={18} className="animate-pulse" />
                Analyzing signals...
              </>
            ) : (
              <>
                Initialize Scan <ArrowRight size={18} />
              </>
            )}
          </button>
        </form>
      </motion.div>

    </div>
  );
};

export default LandingPage;
