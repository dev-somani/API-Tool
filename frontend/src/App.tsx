import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Play,
  Download,
  AlertTriangle,
  Activity,
  XCircle,
  Layers,
  FileCode,
  Upload,
  RefreshCw,
  Eye,
  Sliders,
  Database
} from 'lucide-react';

interface Target {
  id: string;
  name: string;
  base_url: string;
  description?: string;
  created_at: string;
}

interface Scan {
  id: string;
  name: string;
  target_id: string;
  consent_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  mode: 'safe' | 'full';
  spec_type?: string;
  total_endpoints: number;
  tested_endpoints: number;
  progress_pct: number;
  created_at: string;
  error_message?: string;
}

interface Finding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss_score: number;
  owasp_id?: string;
  endpoint_method?: string;
  endpoint_path?: string;
  description: string;
  business_impact: string;
  remediation: string;
  evidence_request?: string;
  evidence_response?: string;
  vector: string;
  is_false_positive: boolean;
}

export default function App() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [activeTab, setActiveTab] = useState<'dashboard' | 'new-scan' | 'findings'>('dashboard');

  // New Scan Form State
  const [targetName, setTargetName] = useState('');
  const [targetUrl, setTargetUrl] = useState('http://localhost:8080');
  const [testerName, setTesterName] = useState('Security Auditor');
  const [testerEmail, setTesterEmail] = useState('auditor@company.com');
  const [hasConsent, setHasConsent] = useState(false);
  const [specType, setSpecType] = useState<'postman' | 'openapi' | 'manual'>('postman');
  const [scanName, setScanName] = useState('My API Assessment');
  const [scanMode, setScanMode] = useState<'safe' | 'full'>('safe');
  const [sessionToken, setSessionToken] = useState('');
  
  // Postman files
  const [collectionContent, setCollectionContent] = useState('');
  const [collectionFileName, setCollectionFileName] = useState('');
  const [envContent, setEnvContent] = useState('');
  const [envFileName, setEnvFileName] = useState('');
  const [manualEndpoints, setManualEndpoints] = useState('/api/users\n/api/orders\n/api/admin/metrics');

  const [loading, setLoading] = useState(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);

  // Findings Search & Filter State
  const [searchTerm, setSearchTerm] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 20;

  useEffect(() => {
    fetchTargets();
    fetchScans();
  }, []);

  // Poll active scans every 1.5 seconds dynamically
  useEffect(() => {
    const isScanning = scans.some((s) => s.status === 'running' || s.status === 'pending') ||
                       selectedScan?.status === 'running' || selectedScan?.status === 'pending';
    if (!isScanning) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch('/api/scans/');
        if (res.ok) {
          const data: Scan[] = await res.json();
          setScans(data);
          // Keep selectedScan in sync so the progress bar moves in real-time
          setSelectedScan((prev) => {
            if (!prev) return data[0] || null;
            const updated = data.find((s) => s.id === prev.id);
            return updated || prev;
          });
        }
        if (selectedScan) {
          fetchScanDetails(selectedScan.id);
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [scans, selectedScan?.id, selectedScan?.status]);

  const fetchTargets = async () => {
    try {
      const res = await fetch('/api/targets/');
      if (res.ok) setTargets(await res.json());
    } catch (e) {
      console.error(e);
    }
  };

  const fetchScans = async () => {
    try {
      const res = await fetch('/api/scans/');
      if (res.ok) {
        const data: Scan[] = await res.json();
        setScans(data);
        const scanToSelect = selectedScan
          ? data.find((s) => s.id === selectedScan.id) || selectedScan
          : data[0] || null;
        setSelectedScan(scanToSelect);
        if (scanToSelect) await fetchScanDetails(scanToSelect.id);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const selectScan = async (scan: Scan) => {
    setSelectedScan(scan);
    await fetchScanDetails(scan.id);
  };

  const deleteSelectedScan = async () => {
    if (!selectedScan) return;
    const confirmed = window.confirm(`Delete scan history for "${selectedScan.name}"? This cannot be undone.`);
    if (!confirmed) return;

    setErrorBanner(null);
    try {
      const res = await fetch(`/api/scans/${selectedScan.id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error(await res.text());

      const remainingScans = scans.filter((scan) => scan.id !== selectedScan.id);
      setScans(remainingScans);
      setSelectedScan(remainingScans[0] || null);
      setFindings([]);
    } catch (err: any) {
      setErrorBanner(`Scan deletion failed: ${err.message || err}`);
    }
  };

  const fetchScanDetails = async (scanId: string) => {
    try {
      const res = await fetch(`/api/scans/${scanId}/findings`);
      if (res.ok) {
        const data = await res.json();
        setFindings(data);
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Handle Postman collection file upload
  const handleCollectionUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setCollectionFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      setCollectionContent(event.target?.result as string || '');
    };
    reader.readAsText(file);
  };

  // Handle Postman environment file upload
  const handleEnvUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setEnvFileName(file.name);
    const reader = new FileReader();
    reader.onload = (event) => {
      setEnvContent(event.target?.result as string || '');
    };
    reader.readAsText(file);
  };

  // Merge Postman collection with environment values
  const resolvePostmanCollection = (collStr: string, envStr: string): string => {
    if (!envStr) return collStr;
    try {
      const envData = JSON.parse(envStr);
      let resolved = collStr;
      const values = envData.values || [];
      for (const item of values) {
        if (item.enabled !== false && item.key) {
          const regex = new RegExp(`\\{\\{\\s*${item.key}\\s*\\}\\}`, 'g');
          resolved = resolved.replace(regex, item.value || '');
        }
      }
      return resolved;
    } catch (e) {
      console.warn('Failed to parse environment file:', e);
      return collStr;
    }
  };

  const handleLaunchScan = async () => {
    setErrorBanner(null);
    if (!hasConsent) {
      setErrorBanner('Authorization Consent is mandatory. You must certify you have written permission to test this target.');
      return;
    }

    if (specType === 'postman' && !collectionContent) {
      setErrorBanner('Please select or upload a Postman Collection JSON file.');
      return;
    }

    setLoading(true);
    try {
      // 1. Create or Find Target
      let targetId = '';
      const existing = targets.find((t) => t.base_url === targetUrl.trim());
      if (existing) {
        targetId = existing.id;
      } else {
        const targetRes = await fetch('/api/targets/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: targetName || `Target ${targetUrl}`,
            base_url: targetUrl.trim(),
            description: 'Created via VAPT Web Console',
            allowed_domains: [targetUrl.replace(/https?:\/\//, '').split('/')[0].split(':')[0]]
          })
        });
        if (!targetRes.ok) throw new Error(await targetRes.text());
        const tData = await targetRes.json();
        targetId = tData.id;
        await fetchTargets();
      }

      // 2. Sign Consent
      const consentRes = await fetch(`/api/targets/${targetId}/consent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_id: targetId,
          tester_name: testerName,
          tester_email: testerEmail,
          authorization_statement: 'I confirm written authorization to test this target.',
          scope_description: `Web Console Scan: ${scanName}`
        })
      });
      if (!consentRes.ok) throw new Error(await consentRes.text());
      const cData = await consentRes.json();
      const consentId = cData.id;

      // 3. Prepare Spec Content
      let finalSpecContent = '';
      if (specType === 'postman') {
        finalSpecContent = resolvePostmanCollection(collectionContent, envContent);
      } else if (specType === 'openapi') {
        finalSpecContent = collectionContent;
      } else if (specType === 'manual') {
        const lines = manualEndpoints.split('\n').map((l) => l.trim()).filter(Boolean);
        finalSpecContent = JSON.stringify(lines.map((p) => ({ method: 'GET', path: p.startsWith('/') ? p : `/${p}` })));
      }

      // 4. Trigger Scan
      const normalizedSessionToken = sessionToken.trim().replace(/^Bearer\s+/i, '');
      const scanRes = await fetch('/api/scans/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_id: targetId,
          consent_id: consentId,
          name: scanName,
          mode: scanMode,
          spec_type: specType,
          spec_content: finalSpecContent,
          auth_configs: normalizedSessionToken ? [{
            role_name: 'user',
            auth_type: 'bearer',
            token: normalizedSessionToken
          }] : [],
          rate_limit_rps: 5.0,
          concurrency: 4
        })
      });

      if (!scanRes.ok) throw new Error(await scanRes.text());
      const newScan = await scanRes.json();
      
      await fetchScans();
      setSelectedScan(newScan);
      setActiveTab('dashboard');
    } catch (err: any) {
      setErrorBanner(`Scan launch failed: ${err.message || err}`);
    } finally {
      setLoading(false);
    }
  };

  // Severity count helpers
  const getSeverityCount = (sev: string) => findings.filter((f) => f.severity.toLowerCase() === sev).length;

  // Findings filter & pagination
  const filteredFindings = findings.filter((f) => {
    if (sevFilter !== 'all' && f.severity.toLowerCase() !== sevFilter.toLowerCase()) return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        (f.endpoint_path || '').toLowerCase().includes(q) ||
        (f.endpoint_method || '').toLowerCase().includes(q) ||
        (f.owasp_id || '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  const totalPages = Math.ceil(filteredFindings.length / pageSize) || 1;
  const paginatedFindings = filteredFindings.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Navigation */}
      <header style={{
        background: 'rgba(15, 23, 42, 0.85)',
        backdropFilter: 'blur(12px)',
        borderBottom: '1px solid var(--border-subtle)',
        padding: '0.85rem 2rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'sticky',
        top: 0,
        zIndex: 50
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{
            background: 'linear-gradient(135deg, #0284c7, #6366f1)',
            padding: '0.5rem',
            borderRadius: '8px',
            display: 'flex'
          }}>
            <ShieldAlert size={22} color="white" />
          </div>
          <div>
            <h1 style={{ fontSize: '1.15rem', fontWeight: 800, letterSpacing: '-0.02em', background: 'linear-gradient(to right, #f8fafc, #94a3b8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              API VAPT SUITE
            </h1>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', letterSpacing: '0.05em' }}>
              VULNERABILITY ASSESSMENT & PENETRATION TESTING
            </span>
          </div>
        </div>

        <nav style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            className={`btn ${activeTab === 'dashboard' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('dashboard')}
          >
            <Activity size={16} /> Dashboard
          </button>
          <button
            className={`btn ${activeTab === 'new-scan' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('new-scan')}
          >
            <Play size={16} /> New Assessment
          </button>
        </nav>
      </header>

      {/* Main Content Area */}
      <main style={{ flex: 1, padding: '1.5rem 2rem', maxWidth: '1400px', margin: '0 auto', width: '100%', boxSizing: 'border-box' }}>
        {errorBanner && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.4)',
            borderRadius: '8px',
            padding: '1rem',
            marginBottom: '1.5rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            color: '#fca5a5'
          }}>
            <AlertTriangle size={20} />
            <span>{errorBanner}</span>
          </div>
        )}

        {activeTab === 'dashboard' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {/* Top Metrics Row */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
              <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minHeight: '110px' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.04em', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ whiteSpace: 'nowrap' }}>ACTIVE SCAN</span>
                  {scans.length > 1 && (
                    <select
                      className="select"
                      style={{ padding: '0.2rem 0.4rem', fontSize: '0.7rem', width: 'auto', maxWidth: '160px', background: 'rgba(0,0,0,0.5)', overflow: 'hidden', textOverflow: 'ellipsis' }}
                      value={selectedScan?.id || ''}
                      onChange={(e) => {
                        const s = scans.find((x) => x.id === e.target.value);
                        if (s) selectScan(s);
                      }}
                    >
                      {scans.map((s) => (
                        <option key={s.id} value={s.id}>
                          {s.name} ({s.status.toUpperCase()})
                        </option>
                      ))}
                    </select>
                  )}
                </div>
                <div style={{ fontSize: '1.15rem', fontWeight: 700, marginTop: '0.35rem', color: '#38bdf8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {selectedScan ? selectedScan.name : 'None Selected'}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  {selectedScan ? `Status: ${selectedScan.status.toUpperCase()}` : 'Launch or select a scan'}
                </div>
              </div>

              <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minHeight: '110px' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.04em' }}>CRITICAL VULNERABILITIES</div>
                <div style={{ fontSize: '1.75rem', fontWeight: 800, marginTop: '0.35rem', color: 'var(--sev-critical)' }}>
                  {getSeverityCount('critical')}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Immediate remediation required</div>
              </div>

              <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minHeight: '110px' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.04em' }}>HIGH SEVERITY</div>
                <div style={{ fontSize: '1.75rem', fontWeight: 800, marginTop: '0.35rem', color: 'var(--sev-high)' }}>
                  {getSeverityCount('high')}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>OWASP API Top 10 breaches</div>
              </div>

              <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minHeight: '110px' }}>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.04em' }}>MEDIUM / LOW</div>
                <div style={{ fontSize: '1.75rem', fontWeight: 800, marginTop: '0.35rem', color: 'var(--sev-medium)' }}>
                  {getSeverityCount('medium') + getSeverityCount('low')}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Misconfigurations & info leaks</div>
              </div>
            </div>

            {/* Scan Progress Bar (if running) */}
            {selectedScan && (
              <div className="card" style={{ borderColor: selectedScan.status === 'running' ? 'rgba(56, 189, 248, 0.4)' : undefined }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                  <div>
                    <span style={{ fontWeight: 700, fontSize: '1rem' }}>{selectedScan.name}</span>
                    <span style={{ marginLeft: '0.75rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      Spec: {selectedScan.spec_type || 'auto'} • Mode: {selectedScan.mode}
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <a
                      href={`/api/reports/${selectedScan.id}/html`}
                      target="_blank"
                      rel="noreferrer"
                      className="btn btn-secondary"
                      style={{ fontSize: '0.75rem', padding: '0.4rem 0.8rem' }}
                    >
                      <Download size={14} /> HTML Report
                    </a>
                    <a
                      href={`/api/reports/${selectedScan.id}/json`}
                      target="_blank"
                      rel="noreferrer"
                      className="btn btn-secondary"
                      style={{ fontSize: '0.75rem', padding: '0.4rem 0.8rem' }}
                    >
                      <FileCode size={14} /> JSON
                    </a>
                    <button
                      className="btn btn-danger"
                      style={{ fontSize: '0.75rem', padding: '0.4rem 0.8rem' }}
                      onClick={deleteSelectedScan}
                      disabled={selectedScan.status === 'running' || selectedScan.status === 'pending'}
                      title={selectedScan.status === 'running' || selectedScan.status === 'pending' ? 'Cancel the scan before deleting it' : 'Delete scan history'}
                    >
                      <XCircle size={14} /> Delete Scan
                    </button>
                  </div>
                </div>

                <div style={{ background: 'rgba(255, 255, 255, 0.08)', borderRadius: '999px', height: '8px', overflow: 'hidden' }}>
                  <div style={{
                    width: `${selectedScan.progress_pct || 0}%`,
                    height: '100%',
                    background: selectedScan.status === 'failed' ? 'var(--sev-critical)' : 'linear-gradient(90deg, #0284c7, #38bdf8)',
                    transition: 'width 0.4s ease'
                  }} />
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  <span>Tested {selectedScan.tested_endpoints} / {selectedScan.total_endpoints} Endpoints</span>
                  <span>{selectedScan.progress_pct.toFixed(1)}% Completed</span>
                </div>
              </div>
            )}

            {/* Findings & Vulnerabilities Table */}
            <div className="card" style={{ overflow: 'hidden', padding: '1.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <ShieldAlert size={18} color="var(--accent-cyan)" /> Detected Vulnerabilities ({findings.length})
                </h3>

                {/* Search & Severity Filters */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <input
                    type="text"
                    className="input"
                    style={{ padding: '0.35rem 0.75rem', fontSize: '0.8rem', width: '200px', background: 'rgba(0,0,0,0.35)' }}
                    placeholder="Search findings..."
                    value={searchTerm}
                    onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
                  />
                  <div style={{ display: 'flex', gap: '0.25rem' }}>
                    {['all', 'critical', 'high', 'medium', 'low'].map((s) => (
                      <button
                        key={s}
                        className={`btn ${sevFilter === s ? 'btn-primary' : 'btn-secondary'}`}
                        style={{ padding: '0.25rem 0.55rem', fontSize: '0.7rem', textTransform: 'uppercase' }}
                        onClick={() => { setSevFilter(s); setCurrentPage(1); }}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {findings.length === 0 ? (
                <div style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <ShieldCheck size={48} style={{ margin: '0 auto 1rem', opacity: 0.4, color: '#10b981' }} />
                  <div>No security findings recorded for this scan yet.</div>
                  <div style={{ fontSize: '0.8rem', marginTop: '0.25rem' }}>Run an assessment to audit for OWASP API vulnerabilities.</div>
                </div>
              ) : (
                <div style={{ width: '100%', overflowX: 'auto' }}>
                  <table style={{ width: '100%', tableLayout: 'fixed', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
                    <colgroup>
                      <col style={{ width: '80px' }} />
                      <col style={{ width: '28%' }} />
                      <col style={{ width: '28%' }} />
                      <col style={{ width: '12%' }} />
                      <col style={{ width: '55px' }} />
                      <col style={{ width: '80px' }} />
                    </colgroup>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                        <th style={{ padding: '0.6rem 0.4rem' }}>Severity</th>
                        <th style={{ padding: '0.6rem 0.4rem' }}>Vulnerability</th>
                        <th style={{ padding: '0.6rem 0.4rem' }}>Endpoint</th>
                        <th style={{ padding: '0.6rem 0.4rem' }}>OWASP</th>
                        <th style={{ padding: '0.6rem 0.4rem', textAlign: 'center' }}>CVSS</th>
                        <th style={{ padding: '0.6rem 0.4rem', textAlign: 'right' }}>Evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedFindings.map((f) => (
                        <tr
                          key={f.id}
                          style={{
                            borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                            cursor: 'pointer',
                            transition: 'background 0.15s'
                          }}
                          onClick={() => setSelectedFinding(f)}
                        >
                          <td style={{ padding: '0.55rem 0.4rem' }}>
                            <span className={`badge badge-${f.severity.toLowerCase()}`} style={{ fontSize: '0.65rem', padding: '0.15rem 0.4rem' }}>
                              {f.severity}
                            </span>
                          </td>
                          <td style={{ padding: '0.55rem 0.4rem', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.8rem' }} title={f.title}>
                            {f.title}
                          </td>
                          <td style={{ padding: '0.55rem 0.4rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#38bdf8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={`${f.endpoint_method} ${f.endpoint_path}`}>
                            <span style={{ fontWeight: 700, marginRight: '0.25rem', color: f.endpoint_method === 'GET' ? '#38bdf8' : '#f59e0b' }}>
                              {f.endpoint_method}
                            </span>
                            {f.endpoint_path}
                          </td>
                          <td style={{ padding: '0.55rem 0.4rem', color: 'var(--text-secondary)', fontSize: '0.75rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {f.owasp_id || 'API Security'}
                          </td>
                          <td style={{ padding: '0.55rem 0.4rem', textAlign: 'center', fontWeight: 700, fontSize: '0.8rem', color: f.cvss_score >= 7 ? 'var(--sev-critical)' : 'var(--sev-medium)' }}>
                            {f.cvss_score}
                          </td>
                          <td style={{ padding: '0.55rem 0.4rem', textAlign: 'right' }}>
                            <button
                              className="btn btn-secondary"
                              style={{ padding: '0.2rem 0.4rem', fontSize: '0.68rem', whiteSpace: 'nowrap' }}
                              onClick={(e) => { e.stopPropagation(); setSelectedFinding(f); }}
                            >
                              <Eye size={11} /> Inspect
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>

                  {/* Pagination Controls */}
                  {totalPages > 1 && (
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      <span>Showing {((currentPage - 1) * pageSize) + 1}–{Math.min(currentPage * pageSize, filteredFindings.length)} of {filteredFindings.length} findings</span>
                      <div style={{ display: 'flex', gap: '0.35rem' }}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }}
                          disabled={currentPage === 1}
                          onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                        >
                          Prev
                        </button>
                        <span style={{ display: 'flex', alignItems: 'center', padding: '0 0.5rem', color: 'var(--text-primary)' }}>
                          Page {currentPage} of {totalPages}
                        </span>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }}
                          disabled={currentPage >= totalPages}
                          onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                        >
                          Next
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* New Assessment Tab */}
        {activeTab === 'new-scan' && (
          <div className="card" style={{ maxWidth: '800px', margin: '0 auto' }}>
            <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '1rem', marginBottom: '1.5rem' }}>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800 }}>Configure New VAPT Assessment</h2>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '0.25rem' }}>
                Ingest API endpoints, configure target authorization scope, and launch defensive vulnerability testing.
              </p>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              {/* Target Details */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.4rem' }}>Target Name</label>
                  <input
                    type="text"
                    className="input"
                    value={targetName}
                    onChange={(e) => setTargetName(e.target.value)}
                    placeholder="e.g. Payments Gateway"
                  />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.4rem' }}>Target Base URL *</label>
                  <input
                    type="text"
                    className="input mono"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="https://api.example.com"
                  />
                </div>
              </div>

              {/* Spec Type Tabs */}
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.4rem' }}>Endpoint Ingestion Source</label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.5rem' }}>
                  <button
                    type="button"
                    className={`btn ${specType === 'postman' ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => setSpecType('postman')}
                  >
                    <FileCode size={16} /> Postman Collection
                  </button>
                  <button
                    type="button"
                    className={`btn ${specType === 'openapi' ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => setSpecType('openapi')}
                  >
                    <Layers size={16} /> OpenAPI / Swagger
                  </button>
                  <button
                    type="button"
                    className={`btn ${specType === 'manual' ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => setSpecType('manual')}
                  >
                    <Sliders size={16} /> Manual Paths
                  </button>
                </div>
              </div>

              {/* Postman Upload Fields */}
              {specType === 'postman' && (
                <div style={{ background: 'rgba(15, 23, 42, 0.5)', padding: '1.25rem', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                  <div style={{ marginBottom: '1rem' }}>
                    <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                      1. Postman Collection JSON (v2.0 or v2.1) *
                    </label>
                    <input
                      type="file"
                      accept=".json"
                      onChange={handleCollectionUpload}
                      style={{ display: 'none' }}
                      id="coll-file"
                    />
                    <label htmlFor="coll-file" className="btn btn-secondary" style={{ width: '100%', cursor: 'pointer' }}>
                      <Upload size={16} /> {collectionFileName || 'Choose Postman Collection File (.json)'}
                    </label>
                  </div>

                  <div>
                    <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.4rem' }}>
                      2. Postman Environment JSON (Optional — auto resolves &#123;&#123;baseUrl&#125;&#125;, &#123;&#123;token&#125;&#125;)
                    </label>
                    <input
                      type="file"
                      accept=".json"
                      onChange={handleEnvUpload}
                      style={{ display: 'none' }}
                      id="env-file"
                    />
                    <label htmlFor="env-file" className="btn btn-secondary" style={{ width: '100%', cursor: 'pointer' }}>
                      <Database size={16} /> {envFileName || 'Choose Postman Environment File (.json)'}
                    </label>
                  </div>
                </div>
              )}

              {/* OpenAPI */}
              {specType === 'openapi' && (
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.4rem' }}>OpenAPI Spec (JSON / YAML)</label>
                  <textarea
                    className="textarea mono"
                    rows={6}
                    value={collectionContent}
                    onChange={(e) => setCollectionContent(e.target.value)}
                    placeholder="Paste OpenAPI 3.0 or Swagger 2.0 JSON or YAML..."
                  />
                </div>
              )}

              {/* Manual */}
              {specType === 'manual' && (
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.4rem' }}>List of Endpoints (One per line)</label>
                  <textarea
                    className="textarea mono"
                    rows={4}
                    value={manualEndpoints}
                    onChange={(e) => setManualEndpoints(e.target.value)}
                    placeholder="/api/v1/auth/login&#10;/api/v1/users/123"
                  />
                </div>
              )}

              {/* Scan Mode */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.4rem' }}>Assessment Mode</label>
                  <select
                    className="select"
                    value={scanMode}
                    onChange={(e: any) => setScanMode(e.target.value)}
                  >
                    <option value="safe">Safe Mode (Read-only / Non-destructive)</option>
                    <option value="full">Full Active Fuzzing (Includes SQLi / Boundary payloads)</option>
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.4rem' }}>Assessment Title</label>
                  <input
                    type="text"
                    className="input"
                    value={scanName}
                    onChange={(e) => setScanName(e.target.value)}
                  />
                </div>
              </div>

              {/* Session Authentication */}
              <div style={{
                background: 'rgba(6, 78, 59, 0.18)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                padding: '1.25rem',
                borderRadius: '8px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 700, color: '#6ee7b7', marginBottom: '0.5rem' }}>
                  <ShieldCheck size={18} /> API Session Authentication
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                  Optional: provide one long-lived Bearer session token to test authenticated endpoints as a user.
                </p>
                <input
                  type="password"
                  className="input mono"
                  value={sessionToken}
                  onChange={(e) => setSessionToken(e.target.value)}
                  placeholder="Paste session token (Bearer prefix optional)"
                  autoComplete="off"
                />
                <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                  The token is sent only with this scan and is not displayed after submission.
                </p>
              </div>

              {/* MANDATORY CONSENT GATE */}
              <div style={{
                background: 'rgba(30, 58, 138, 0.2)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                padding: '1.25rem',
                borderRadius: '8px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 700, color: '#93c5fd', marginBottom: '0.5rem' }}>
                  <ShieldCheck size={18} /> Scope & Written Authorization Consent Gate
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.85rem' }}>
                  This defensive security tool sends real HTTP traffic including fuzzing and bypass payloads. You must certify that you are the owner or have explicit written permission from the owner to assess this target.
                </p>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '0.75rem' }}>
                  <input
                    type="text"
                    className="input"
                    placeholder="Tester Name"
                    value={testerName}
                    onChange={(e) => setTesterName(e.target.value)}
                  />
                  <input
                    type="email"
                    className="input"
                    placeholder="Tester Email"
                    value={testerEmail}
                    onChange={(e) => setTesterEmail(e.target.value)}
                  />
                </div>

                <label style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', cursor: 'pointer', fontSize: '0.85rem', fontWeight: 600, color: 'white' }}>
                  <input
                    type="checkbox"
                    checked={hasConsent}
                    onChange={(e) => setHasConsent(e.target.checked)}
                    style={{ width: '18px', height: '18px', accentColor: '#0284c7' }}
                  />
                  I confirm that I have authorized, written consent to test the specified API endpoints.
                </label>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setActiveTab('dashboard')}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={loading || !hasConsent}
                  onClick={handleLaunchScan}
                >
                  {loading ? <RefreshCw className="animate-pulse" size={16} /> : <Play size={16} />}
                  Launch Penetration Test
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Evidence Drawer / Modal */}
        {selectedFinding && (
          <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            justifyContent: 'flex-end',
            zIndex: 100
          }}>
            <div style={{
              width: '100%',
              maxWidth: '680px',
              background: 'var(--bg-secondary)',
              height: '100%',
              padding: '2rem',
              overflowY: 'auto',
              borderLeft: '1px solid var(--border-subtle)',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.25rem'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <span className={`badge badge-${selectedFinding.severity.toLowerCase()}`}>
                    {selectedFinding.severity}
                  </span>
                  <h2 style={{ fontSize: '1.3rem', fontWeight: 800, marginTop: '0.5rem' }}>{selectedFinding.title}</h2>
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    OWASP: {selectedFinding.owasp_id || 'N/A'} • Vector: {selectedFinding.vector}
                  </div>
                </div>
                <button
                  className="btn btn-secondary"
                  style={{ padding: '0.4rem 0.6rem' }}
                  onClick={() => setSelectedFinding(null)}
                >
                  <XCircle size={18} />
                </button>
              </div>

              <div>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Affected Endpoint</h4>
                <div style={{ background: 'rgba(0,0,0,0.4)', padding: '0.75rem', borderRadius: '6px', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: '#38bdf8', marginTop: '0.25rem' }}>
                  {selectedFinding.endpoint_method} {selectedFinding.endpoint_path}
                </div>
              </div>

              <div>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Description</h4>
                <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>{selectedFinding.description}</p>
              </div>

              <div>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Business Impact</h4>
                <p style={{ fontSize: '0.9rem', color: '#fca5a5', marginTop: '0.25rem' }}>{selectedFinding.business_impact}</p>
              </div>

              <div>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Remediation Guidance</h4>
                <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '0.85rem', borderRadius: '6px', color: '#6ee7b7', fontSize: '0.85rem', marginTop: '0.25rem' }}>
                  {selectedFinding.remediation}
                </div>
              </div>

              {selectedFinding.evidence_request && (
                <div>
                  <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Proof-of-Concept Request (cURL)</h4>
                  <pre style={{ background: '#020617', padding: '0.85rem', borderRadius: '6px', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#e2e8f0', overflowX: 'auto', marginTop: '0.25rem' }}>
                    {selectedFinding.evidence_request}
                  </pre>
                </div>
              )}

              {selectedFinding.evidence_response && (
                <div>
                  <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Target Response Evidence</h4>
                  <pre style={{ background: '#020617', padding: '0.85rem', borderRadius: '6px', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: '#cbd5e1', overflowX: 'auto', marginTop: '0.25rem', maxHeight: '200px' }}>
                    {selectedFinding.evidence_response}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
