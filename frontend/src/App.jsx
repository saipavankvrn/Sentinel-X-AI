import React, { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ packets_monitored: 0, threats_detected: 0, threats_blocked: 0 });
  const [error, setError] = useState(null);
  const [expandedRows, setExpandedRows] = useState([]);

  const toggleRow = (id) => {
    setExpandedRows(prev => prev.includes(id) ? prev.filter(r => r !== id) : [...prev, id]);
  };

  const fetchDashboardData = async () => {
    try {
      // Fetch alerts
      const alertsResponse = await fetch('http://127.0.0.1:8001/alerts');
      if (!alertsResponse.ok) throw new Error('Alerts network response was not ok');
      const alertsData = await alertsResponse.json();
      
      // We reverse the alerts array so newest is at the top of the table
      setAlerts(alertsData.reverse());

      // Fetch stats
      const statsResponse = await fetch('http://127.0.0.1:8001/stats');
      if (!statsResponse.ok) throw new Error('Stats network response was not ok');
      const statsData = await statsResponse.json();
      setStats(statsData);
      
      setError(null);
    } catch (err) {
      console.error('Failed to fetch dashboard data:', err);
      setError('Connection lost. Retrying...');
    }
  };

  const downloadReport = () => {
    const timestamp = new Date().toLocaleString();
    const htmlHeader = `
      <html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
      <head><meta charset='utf-8'><title>Sentinel-X Security Report</title>
      <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        h1 { color: #0056b3; border-bottom: 2px solid #0056b3; padding-bottom: 10px; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background-color: #0056b3; color: white; padding: 10px; text-align: left; }
        td { border-bottom: 1px solid #dee2e6; padding: 10px; }
        .status-BLOCKED { color: #dc3545; font-weight: bold; }
        .status-WARNING { color: #ffc107; font-weight: bold; }
        .status-SAFE { color: #28a745; font-weight: bold; }
        .explanation { font-style: italic; color: #6c757d; font-size: 0.9em; background-color: #fef9e7; padding: 5px; }
      </style>
      </head><body>
    `;
    
    let content = `
      <h1>🛡️ Sentinel-X Cyber Security Report</h1>
      <p><strong>Generated on:</strong> ${timestamp}</p>
      
      <div class="summary">
        <h3>📊 Executive Summary</h3>
        <p>Total Packets Monitored: ${stats.packets_monitored}</p>
        <p>Total Threats Detected: ${stats.threats_detected}</p>
        <p>Total Threats Blocked: ${stats.threats_blocked}</p>
      </div>

      <h3>🚨 Detailed Activity Log</h3>
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Source IP</th>
            <th>Protocol</th>
            <th>Length</th>
            <th>Status</th>
            <th>Type</th>
          </tr>
        </thead>
        <tbody>
    `;

    alerts.forEach(alert => {
      content += `
        <tr>
          <td>${alert.timestamp}</td>
          <td>${alert.source_ip}</td>
          <td>${alert.protocol}</td>
          <td>${alert.packet_length} B</td>
          <td><span class="status-${alert.status}">${alert.status}</span></td>
          <td>${alert.alert_type}</td>
        </tr>
        ${alert.explanation && (alert.status === 'WARNING' || alert.status === 'BLOCKED') ? 
          `<tr><td colspan="6" class="explanation"><strong>AI Analysis:</strong> ${alert.explanation}</td></tr>` : ''}
      `;
    });

    content += `</tbody></table></body></html>`;

    const blob = new Blob(['\ufeff', htmlHeader + content], {
      type: 'application/msword'
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Sentinel-X_Report_${new Date().toISOString().split('T')[0]}.doc`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleUnblock = async (ip) => {
    try {
      const response = await fetch('http://127.0.0.1:8001/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await response.json();
      if (data.status === 'success') {
        fetchDashboardData(); // Refresh UI
      } else {
        alert(data.message);
      }
    } catch (err) {
      console.error('Unblock failed:', err);
    }
  };

  // Auto refresh every 2 seconds
  useEffect(() => {
    fetchDashboardData(); // Initial fetch
    const intervalId = setInterval(fetchDashboardData, 2000);
    return () => clearInterval(intervalId);
  }, []);

  const getBadgeClass = (status) => {
    switch (status) {
      case 'SAFE': return 'status-badge badge-safe';
      case 'WARNING':
      case 'DETECTED': return 'status-badge badge-detected';
      case 'BLOCKED': return 'status-badge badge-blocked';
      default: return 'status-badge badge-safe';
    }
  };

  const getRowClass = (status) => {
    switch (status) {
      case 'WARNING':
      case 'DETECTED': return 'main-row row-detected';
      case 'BLOCKED': return 'main-row row-blocked';
      default: return 'main-row';
    }
  };

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <h1 className="dashboard-title">Sentinel-X Cyber Threat Monitor</h1>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <button className="download-btn" onClick={downloadReport}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
            Download Report
          </button>
          <div className="status-indicator">
            <div className="pulse"></div>
            {error ? <span style={{ color: 'var(--danger-color)' }}>{error}</span> : <span>System Active</span>}
          </div>
        </div>
      </header>

      {/* Metrics Section */}
      <section className="metrics-container">
        <div className="metric-box">
          <div className="metric-title">Packets Monitored</div>
          <div className="metric-value">{stats.packets_monitored.toLocaleString()}</div>
        </div>
        <div className="metric-box">
          <div className="metric-title">Threats Detected</div>
          <div className="metric-value warning-text">{stats.threats_detected.toLocaleString()}</div>
        </div>
        <div className="metric-box">
          <div className="metric-title">Threats Blocked</div>
          <div className="metric-value danger-text">{stats.threats_blocked.toLocaleString()}</div>
        </div>
      </section>

      {/* Main Section */}
      <main>
        <h3>Real-Time Network Traffic</h3>
        {alerts.length === 0 && !error ? (
          <div className="empty-state">
            <p>The network is currently secure. Listening for incoming traffic...</p>
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="threat-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Protocol</th>
                  <th>Packet Length</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert, index) => {
                  const isExpandable = alert.status === 'WARNING' || alert.status === 'BLOCKED' || alert.status === 'DETECTED';
                  const rowId = `${alert.timestamp}-${alert.source_ip}-${alert.destination_ip}-${alert.packet_length}`;
                  const isExpanded = expandedRows.includes(rowId);

                  return (
                    <React.Fragment key={index}>
                      <tr 
                        className={`${getRowClass(alert.status)} ${isExpandable ? 'clickable-row' : ''} ${isExpanded ? 'expanded-active' : ''}`}
                        onClick={() => isExpandable && toggleRow(rowId)}
                      >
                        <td className="time-col">{alert.timestamp}</td>
                        <td className="ip-col">{alert.source_ip}</td>
                        <td className="ip-col">{alert.destination_ip}</td>
                        <td>{alert.protocol || 'Unknown'}</td>
                        <td>{alert.packet_length} B</td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span className={getBadgeClass(alert.status)}>
                              {alert.status === 'BLOCKED' ? 'ATTACK BLOCKED' : 
                               alert.status === 'DETECTED' ? 'DETECTED' : alert.status}
                            </span>
                            {isExpandable && (
                              <svg 
                                width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" 
                                style={{ transform: isExpanded ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform 0.2s', opacity: 0.6 }}
                              ><polyline points="6 9 12 15 18 9"></polyline></svg>
                            )}
                          </div>
                        </td>
                      </tr>
                      {isExpandable && isExpanded && (
                        <tr className="details-row">
                          <td colSpan="6" className="expanded-highlight">
                            <div style={{ display: 'flex', gap: '3rem', fontSize: '0.9rem', alignItems: 'flex-start' }}>
                              <div style={{ minWidth: '150px' }}>
                                <strong style={{ color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: '0.8rem', display: 'block', marginBottom: '6px' }}>Trigger:</strong>
                                <span style={{ color: '#e6edf3', fontWeight: '500' }}>{alert.alert_type}</span>
                              </div>
                              <div style={{ minWidth: '120px' }}>
                                <strong style={{ color: 'var(--text-secondary)', textTransform: 'uppercase', fontSize: '0.8rem', display: 'block', marginBottom: '6px' }}>⏱️ Latency:</strong>
                                <span style={{ color: '#e6edf3', fontWeight: '500' }}>{alert.latency ? `${alert.latency.toFixed(2)} ms` : 'N/A'}</span>
                              </div>
                              {alert.explanation && (
                                <div style={{ flex: 1 }}>
                                  <strong style={{ color: '#a371f7', textTransform: 'uppercase', fontSize: '0.8rem', display: 'block', marginBottom: '6px' }}>🛡️ AI Analysis:</strong>
                                  <span style={{ color: '#c9d1d9', lineHeight: '1.5' }}>{alert.explanation}</span>
                                </div>
                              )}
                              {alert.status === 'BLOCKED' && (
                                <button className="unblock-btn" onClick={(e) => { e.stopPropagation(); handleUnblock(alert.source_ip); }}>
                                  Unblock IP
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
