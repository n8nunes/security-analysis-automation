import React, { useState } from 'react';
import { useLocation, useNavigate, Navigate } from 'react-router-dom';
import { ArrowLeft, Download, ShieldCheck, ShieldAlert, Shield, ChevronDown, ChevronRight, CheckCircle2, XCircle, AlertCircle } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const ControlItem = ({ control }) => {
  const [expanded, setExpanded] = useState(false);
  
  const isFound = control.status === 'SIGNAL_FOUND';
  const isMissing = control.status === 'SIGNAL_NOT_FOUND';
  
  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-panel"
      style={{ 
        marginBottom: '0.75rem', 
        overflow: 'hidden',
        borderLeft: isFound ? '4px solid var(--success)' : (isMissing ? '4px solid var(--warning)' : '4px solid var(--danger)')
      }}
    >
      <div 
        onClick={() => setExpanded(!expanded)}
        style={{ 
          padding: '1.25rem', 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center',
          cursor: 'pointer',
          background: expanded ? 'var(--bg-card-hover)' : 'transparent'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flex: 1 }}>
          <div style={{ minWidth: '80px', fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>
            {control.control_id}
          </div>
          <div style={{ fontWeight: 500 }}>
            {control.control_name}
          </div>
        </div>
        
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
          {isFound ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--success)', fontSize: '13px', fontWeight: 500 }}>
              <CheckCircle2 size={16} /> Signal Found
            </div>
          ) : (
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--warning)', fontSize: '13px', fontWeight: 500 }}>
              <AlertCircle size={16} /> Not Found
            </div>
          )}
          
          <div style={{ width: '40px', textAlign: 'right' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)' }}>{control.score}</span>
          </div>
          
          <div style={{ color: 'var(--text-muted)' }}>
            {expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
          </div>
        </div>
      </div>
      
      <AnimatePresence>
        {expanded && (
          <motion.div 
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            style={{ overflow: 'hidden' }}
          >
            <div style={{ padding: '0 1.25rem 1.25rem', borderTop: '1px solid var(--border-glass)', marginTop: '0.5rem', paddingTop: '1.25rem' }}>
              
              {control.evidence && control.evidence.length > 0 ? (
                <div>
                  <h4 style={{ fontSize: '12px', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                    Collected Evidence
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    {control.evidence.map((ev, i) => (
                      <div key={i} style={{ background: 'var(--bg-glass)', padding: '1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-glass)' }}>
                        <div style={{ fontStyle: 'italic', marginBottom: '0.5rem', color: 'var(--text-primary)', borderLeft: '3px solid var(--primary)', paddingLeft: '0.75rem' }}>
                          "{ev.quote}"
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)' }}>
                          <span>Origin: <strong>{ev.signal_origin.toUpperCase()}</strong></span>
                          <span>Confidence: <strong>{(ev.confidence * 100).toFixed(0)}%</strong></span>
                          <span>Source: {ev.source_type}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div style={{ color: 'var(--text-secondary)', fontSize: '14px' }}>
                  No public evidence detected for this control. 
                  {control.gap_narrative && (
                    <div style={{ marginTop: '1rem', padding: '1rem', background: 'var(--warning-light)', color: 'var(--text-primary)', borderRadius: 'var(--radius-sm)', borderLeft: '3px solid var(--warning)' }}>
                      <strong>AI Gap Analysis:</strong> {control.gap_narrative}
                    </div>
                  )}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};


const Dashboard = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const scanResult = location.state?.scanResult;

  if (!scanResult || scanResult.error || !scanResult.controls) {
    return <Navigate to="/" replace />;
  }

  const {
    domain,
    scan_timestamp,
    overall_posture_rating,
    metadata,
    function_scores,
    controls,
    gaps,
    llm_extraction_notes,
    disclaimer
  } = scanResult;

  const foundCount = controls.filter(c => c.status === 'SIGNAL_FOUND').length;
  
  const getScoreColor = (score) => {
    if (score >= 80) return 'var(--success)';
    if (score >= 50) return 'var(--warning)';
    return 'var(--danger)';
  };

  return (
    <div style={{ maxWidth: '1100px', margin: '0 auto', padding: '2rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3rem' }}>
        <div>
          <button 
            onClick={() => navigate('/')} 
            style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)', marginBottom: '1rem', fontSize: '14px', fontWeight: 500 }}
          >
            <ArrowLeft size={16} /> New Scan
          </button>
          <h1 style={{ fontSize: '2.5rem', margin: 0, lineHeight: 1.2 }}>{metadata.company_name}</h1>
          <div style={{ color: 'var(--text-muted)', fontSize: '15px' }}>{domain}</div>
        </div>
        
        <div style={{ textAlign: 'right' }}>
          <div style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Scan Completed</div>
          <div style={{ fontWeight: 500 }}>{new Date(scan_timestamp).toLocaleString()}</div>
        </div>
      </div>

      {/* Hero Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr', gap: '1.5rem', marginBottom: '3rem' }}>
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="glass-panel" 
          style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', padding: '2.5rem', position: 'relative', overflow: 'hidden' }}
        >
          <div style={{ position: 'absolute', top: '-20%', right: '-10%', opacity: 0.05 }}>
            <Shield size={250} />
          </div>
          <div style={{ fontSize: '4.5rem', fontWeight: 600, color: getScoreColor(overall_posture_rating), lineHeight: 1 }}>
            {overall_posture_rating}
          </div>
          <div style={{ fontSize: '14px', textTransform: 'uppercase', letterSpacing: '1px', fontWeight: 600, color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
            Overall Posture Rating
          </div>
        </motion.div>

        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.1 }}
          className="glass-panel" 
          style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', padding: '2rem' }}
        >
          <ShieldCheck size={40} color="var(--success)" style={{ marginBottom: '1rem' }} />
          <div style={{ fontSize: '2.5rem', fontWeight: 600, lineHeight: 1 }}>{foundCount}</div>
          <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>Signals Found</div>
        </motion.div>
        
        <motion.div 
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.2 }}
          className="glass-panel" 
          style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', padding: '2rem' }}
        >
          <ShieldAlert size={40} color="var(--warning)" style={{ marginBottom: '1rem' }} />
          <div style={{ fontSize: '2.5rem', fontWeight: 600, lineHeight: 1 }}>{gaps.length}</div>
          <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>Identified Gaps</div>
        </motion.div>
      </div>

      {/* Function Breakdown */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        style={{ marginBottom: '4rem' }}
      >
        <h3 style={{ fontSize: '1.25rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
          NIST Function Breakdown
        </h3>
        <div className="glass-panel" style={{ padding: '2rem' }}>
          {Object.entries(function_scores).map(([func, score], idx) => (
            <div key={func} style={{ display: 'grid', gridTemplateColumns: '100px 1fr 60px', alignItems: 'center', gap: '1.5rem', marginBottom: idx !== 4 ? '1.5rem' : 0 }}>
              <div style={{ fontWeight: 500 }}>{func}</div>
              <div style={{ height: '12px', background: 'var(--bg-glass)', borderRadius: '6px', overflow: 'hidden' }}>
                <motion.div 
                  initial={{ width: 0 }}
                  animate={{ width: `${score}%` }}
                  transition={{ duration: 1, delay: 0.5 + (idx * 0.1) }}
                  style={{ height: '100%', background: getScoreColor(score), borderRadius: '6px' }}
                />
              </div>
              <div style={{ fontWeight: 600, textAlign: 'right' }}>{score}</div>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Controls List */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        style={{ marginBottom: '4rem' }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '1.5rem' }}>
          <h3 style={{ fontSize: '1.25rem', margin: 0 }}>Control Assessment ({controls.length} total)</h3>
        </div>
        
        <div>
          {controls.map((control) => (
            <ControlItem key={control.control_id} control={control} />
          ))}
        </div>
      </motion.div>

      {/* Gaps Section */}
      {gaps.length > 0 && (
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          style={{ marginBottom: '4rem' }}
        >
          <h3 style={{ fontSize: '1.25rem', marginBottom: '1.5rem', color: 'var(--danger)' }}>
            Gaps Requiring Attention ({gaps.length} controls)
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {gaps.map((gap, i) => (
              <div key={i} className="glass-panel" style={{ padding: '1.5rem', borderLeft: '4px solid var(--danger)' }}>
                <div style={{ fontSize: '14px', fontWeight: 600, marginBottom: '0.5rem' }}>
                  {gap.gap_description} ({gap.control_id})
                </div>
                <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  {gap.gap_narrative}
                </div>
                <div style={{ marginTop: '1rem', fontSize: '12px', fontWeight: 500, color: 'var(--primary)' }}>
                  Suggested Action: {gap.suggested_remediation}
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Footer / Notes */}
      <div style={{ borderTop: '1px solid var(--border-glass)', paddingTop: '2rem', paddingBottom: '2rem' }}>
        {llm_extraction_notes && (
          <div style={{ padding: '1rem', background: 'var(--primary-light)', borderRadius: 'var(--radius-sm)', fontSize: '13px', marginBottom: '1rem' }}>
            <strong style={{ color: 'var(--primary)' }}>AI Processing Note:</strong> {llm_extraction_notes}
          </div>
        )}
        <p style={{ fontSize: '11px', color: 'var(--text-muted)', lineHeight: 1.5, textAlign: 'justify' }}>
          {disclaimer}
        </p>
      </div>

    </div>
  );
};

export default Dashboard;
