import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const httpURL = import.meta.env.VITE_DETECTOR_HTTP_URL || "http://localhost:8080";
const wsURL = import.meta.env.VITE_DETECTOR_WS_URL || "ws://localhost:8080/ws";
const demoAlerts = [
  { id: "demo-1", timestamp: new Date().toISOString(), severity: "critical", rule: "credential_stuffing", source_ip: "203.0.113.42", message: "Repeated authentication failures across multiple credentials", metadata: { attempts: 18 } },
  { id: "demo-2", timestamp: new Date(Date.now() - 19000).toISOString(), severity: "critical", rule: "sql_injection", source_ip: "198.51.100.8", message: "Known malicious payload signature detected", metadata: { location: "query" } },
  { id: "demo-3", timestamp: new Date(Date.now() - 51000).toISOString(), severity: "high", rule: "sequential_scraping", source_ip: "192.0.2.119", message: "Near-sequential product resources requested", metadata: { sequence_length: 24 } },
  { id: "demo-4", timestamp: new Date(Date.now() - 78000).toISOString(), severity: "medium", rule: "rate_limit", source_ip: "203.0.113.42", message: "Request rate exceeded configured threshold", metadata: { requests: 147 } },
];

function useSentinel() {
  const [alerts, setAlerts] = useState([]);
  const [summary, setSummary] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0 });
  const [connected, setConnected] = useState(false);
  const [demo, setDemo] = useState(false);
  useEffect(() => {
    let active = true, socket, retry;
    Promise.all([fetch(`${httpURL}/api/alerts?limit=100`), fetch(`${httpURL}/api/summary`)]).then(async ([a, s]) => {
      if (!a.ok || !s.ok) throw new Error("API unavailable");
      const [items, totals] = await Promise.all([a.json(), s.json()]);
      if (active) { setAlerts(items); setSummary(totals); }
    }).catch(() => {
      if (active && location.hostname !== "localhost" && location.hostname !== "127.0.0.1") {
        setAlerts(demoAlerts);
        setSummary({ total: 37, critical: 5, high: 11, medium: 18, low: 3 });
        setDemo(true);
      }
    });
    const connect = () => {
      socket = new WebSocket(wsURL);
      socket.onopen = () => active && setConnected(true);
      socket.onmessage = event => {
        const alert = JSON.parse(event.data);
        if (!active) return;
        setAlerts(current => [alert, ...current.filter(item => item.id !== alert.id)].slice(0, 100));
        setSummary(current => ({ ...current, total: current.total + 1, [alert.severity]: (current[alert.severity] || 0) + 1 }));
      };
      socket.onclose = () => { if (active) { setConnected(false); if (!demo && location.hostname === "localhost") retry = setTimeout(connect, 3000); } };
      socket.onerror = () => socket.close();
    };
    connect();
    return () => { active = false; clearTimeout(retry); socket?.close(); };
  }, []);
  return { alerts, summary, connected, demo };
}

const label = value => value.replaceAll("_", " ");
function App() {
  const { alerts, summary, connected, demo } = useSentinel();
  const sources = useMemo(() => Object.entries(alerts.reduce((all, alert) => ({ ...all, [alert.source_ip]: (all[alert.source_ip] || 0) + 1 }), {})).sort((a,b) => b[1]-a[1]).slice(0,4), [alerts]);
  const maxSource = Math.max(1, ...sources.map(([, count]) => count));
  return <div className="console">
    <header><a className="brand" href="#top"><span className="brand-eye">S</span><span>SENTINEL<small>API DEFENSE GRID</small></span></a><div className="system-line"><i className={connected || demo ? "" : "offline"}/> {demo ? "PORTFOLIO DEMO // SAMPLE DATA" : `DETECTOR ${connected ? "ONLINE" : "RECONNECTING"}`}</div><div className="clock">{new Date().toLocaleTimeString([], { hour12:false })}</div></header>
    <aside><nav><a className="active" href="#overview">01 / OVERVIEW</a><a href="#alerts">02 / ALERT FEED</a><a href="#sources">03 / SOURCES</a></nav><section className="stack"><p>ACTIVE STACK</p><span>Kafka <i /></span><span>Redis <i /></span><span>Postgres <i /></span><span>Detector <i className={connected ? "" : "offline"}/></span></section><p className="build">BUILD 1.0.0 // LIVE</p></aside>
    <main id="overview"><div className="title-row"><div><p className="kicker">LIVE THREAT INTELLIGENCE</p><h1>Threat surface<br/><em>under watch.</em></h1></div><div className="radar" aria-hidden="true"><span /></div></div>
      <section className="metrics"><article><span>ALERTS / 24H</span><strong>{summary.total}</strong><small>PERSISTED DETECTIONS</small></article><article className="alert-metric"><span>CRITICAL</span><strong>{summary.critical}</strong><small>REQUIRES ATTENTION</small></article><article><span>HIGH SEVERITY</span><strong>{summary.high}</strong><small>LAST 24 HOURS</small></article><article><span>LIVE BUFFER</span><strong>{alerts.length}</strong><small>MOST RECENT ALERTS</small></article></section>
      <section className="workspace" id="sources"><div className="signal-panel"><div className="panel-head"><div><p>DETECTION PROFILE</p><h2>Severity distribution</h2></div><span>LAST 24 HOURS</span></div><div className="severity-bars">{["critical","high","medium","low"].map(level => <div key={level}><span>{level}</span><i style={{width:`${summary.total ? Math.max(2, summary[level] / summary.total * 100) : 0}%`}}/><b>{summary[level]}</b></div>)}</div></div>
        <div className="sources"><div className="panel-head"><div><p>HOT SOURCES</p><h2>Top origin IPs</h2></div></div>{sources.length ? sources.map(([ip,count],i)=><div className="source" key={ip}><span>0{i+1}</span><b>{ip}</b><i style={{width:`${count/maxSource*72}%`}}/><small>{count} alerts</small></div>) : <p className="empty">No threats detected yet.</p>}</div></section>
      <section className="feed" id="alerts"><div className="panel-head"><div><p>DETECTION STREAM</p><h2>Latest alerts</h2></div><span className="live"><i className={connected || demo ? "" : "offline"}/> {demo ? "DEMO FEED" : connected ? "LIVE FEED" : "OFFLINE"}</span></div>{alerts.length ? alerts.slice(0,25).map(a=><article key={a.id}><time>{new Date(a.timestamp).toLocaleTimeString([], {hour12:false})}</time><span className={`severity ${a.severity}`}>{a.severity}</span><strong>{label(a.rule)}</strong><code>{a.source_ip}</code><span>{a.message}</span><button title={JSON.stringify(a.metadata)} aria-label={`Inspect ${a.rule}`}>↗</button></article>) : <p className="empty feed-empty">Waiting for the first detection…</p>}</section>
    </main>
  </div>;
}
createRoot(document.getElementById("root")).render(<React.StrictMode><App /></React.StrictMode>);
