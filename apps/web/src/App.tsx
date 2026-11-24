import { ChangeEvent, FormEvent, useCallback, useEffect, useMemo, useState } from "react";

type User = { id: string; tenantId: string; email: string; role: string };
type Sbom = { _id: string; format: "cyclonedx" | "spdx"; formatVersion: string; documentName: string; documentVersion?: string; componentCount: number; documentDigest?: string; ingestionStatus: string; createdAt: string };
type Health = { status: string; database: string; service: string };
type Finding = { purl: string; id: string; summary?: string; aliases: string[]; severity: string; cvssScore?: number; epssScore?: number; epssPercentile?: number; isKnownExploited: boolean; references: string[] };
type ScanResult = { status: string; scanId: string; scannedAt: string; scannedPackages: number; vulnerablePackages: number; findingCount: number; findings: Finding[] };
type Verification = { _id: string; artifactDigest: string; verificationType: string; status: string; certificateIdentity?: string; builderId?: string; failureCode?: string; createdAt: string };
const API = import.meta.env.VITE_API_BASE_URL ?? "";

async function api<T>(path: string, token?: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers
    }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error ?? `Request failed (${response.status})`);
  return body as T;
}

export default function App() {
  const [token, setToken] = useState("");
  const [user, setUser] = useState<User | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [sboms, setSboms] = useState<Sbom[]>([]);
  const [latestScan, setLatestScan] = useState<ScanResult | null>(null);
  const [verificationHistory, setVerificationHistory] = useState<Verification[]>([]);
  const [selectedSbom, setSelectedSbom] = useState("");
  const [search, setSearch] = useState("");
  const [formatFilter, setFormatFilter] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ format: "cyclonedx", formatVersion: "1.6", documentName: "", documentVersion: "", componentCount: "0", documentDigest: "" });

  const refresh = useCallback(async (accessToken: string, q = "", format = "") => {
    const params = new URLSearchParams({ limit: "50" });
    if (q.trim()) params.set("q", q.trim());
    if (format) params.set("format", format);
    const [h, list, trust] = await Promise.all([
      api<Health>("/api/health"),
      api<{ items: Sbom[] }>(`/api/sboms?${params.toString()}`, accessToken),
      api<{ items: Verification[] }>("/api/trust/verifications?limit=10", accessToken)
    ]);
    setHealth(h);
    setSboms(list.items);
    setVerificationHistory(trust.items);
  }, []);

  useEffect(() => {
    api<Health>("/api/health").then(setHealth).catch(() => setHealth(null));
  }, []);

  const totalComponents = useMemo(() => sboms.reduce((sum, item) => sum + item.componentCount, 0), [sboms]);

  async function signIn(event: FormEvent) {
    event.preventDefault(); setBusy(true); setNotice("");
    try {
      const result = await api<{ accessToken: string; user: User }>("/api/auth/login", undefined, {
        method: "POST", body: JSON.stringify({ tenantId, email, password })
      });
      setToken(result.accessToken); setUser(result.user); setPassword("");
      await refresh(result.accessToken);
      setNotice("Signed in. Your tenant-scoped SBOM workspace is ready.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "Sign-in failed"); }
    finally { setBusy(false); }
  }

  async function submitSbom(event: FormEvent) {
    event.preventDefault(); if (!token) return;
    setBusy(true); setNotice("");
    try {
      const payload = { ...form, componentCount: Number(form.componentCount) };
      await api("/api/sboms", token, { method: "POST", body: JSON.stringify(payload) });
      setForm({ format: "cyclonedx", formatVersion: "1.6", documentName: "", documentVersion: "", componentCount: "0", documentDigest: "" });
      await refresh(token);
      setNotice("SBOM metadata saved to your tenant inventory. Upload a CycloneDX or SPDX JSON document to enable package analysis.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "Could not save SBOM metadata"); }
    finally { setBusy(false); }
  }

  async function uploadSbomDocument(event: ChangeEvent<HTMLInputElement>) {
    const input = event.currentTarget;
    const file = input.files?.[0];
    if (!file || !token) return;
    setBusy(true); setNotice("");
    try {
      if (file.size > 2 * 1024 * 1024) throw new Error("SBOM JSON file must be 2 MiB or smaller.");
      const document = JSON.parse(await file.text()) as unknown;
      await api("/api/sboms/document", token, { method: "POST", body: JSON.stringify({ document, source: file.name }) });
      await refresh(token, search, formatFilter);
      setNotice("SBOM JSON parsed, normalized and saved. Raw document bytes are not retained.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "Could not ingest SBOM JSON"); }
    finally { setBusy(false); input.value = ""; }
  }

  async function scanSbom(id: string) {
    if (!token) return;
    setBusy(true); setNotice(""); setSelectedSbom(id);
    try {
      const result = await api<ScanResult>(`/api/sboms/${id}/vulnerabilities`, token, { method: "POST" });
      setLatestScan(result);
      setNotice(`OSV scan completed: ${result.findingCount} findings across ${result.scannedPackages} packages.`);
    } catch (error) { setNotice(error instanceof Error ? error.message : "Vulnerability scan failed"); }
    finally { setBusy(false); }
  }

  async function exportCsv() {
    if (!token) return;
    try {
      const response = await fetch(`${API}/api/sboms/export.csv`, { headers: { Authorization: `Bearer ${token}` } });
      if (!response.ok) throw new Error("Could not export this tenant inventory");
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url; link.download = "chainproof-sbom-inventory.csv";
      document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(url);
      setNotice("Tenant-scoped SBOM CSV export is ready.");
    } catch (error) { setNotice(error instanceof Error ? error.message : "Export failed"); }
  }

  function signOut() { setToken(""); setUser(null); setSboms([]); setLatestScan(null); setVerificationHistory([]); setNotice("Signed out."); }

  return <main className="shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">C</span><div><strong>ChainProof</strong><small>TRUST OPERATIONS</small></div></div>
      <div className="nav-label">WORKSPACE</div>
      <div className="nav-item active"><span>◈</span> Command center</div>
      <div className="nav-item"><span>▤</span> SBOM inventory</div>
      <div className="nav-item"><span>⌁</span> Provenance</div>
      <div className="nav-item"><span>⌖</span> Vulnerability intel</div>
      <div className="sidebar-bottom"><span className="status-dot"></span> API workspace <small>{health?.database ?? "checking"}</small></div>
    </aside>
    <section className="content">
      <header className="topbar"><div><span className="eyebrow">SECURITY / OVERVIEW</span><h1>Software supply chain command center</h1></div>
        {user ? <div className="user-chip"><span className="avatar">{user.email.slice(0,1).toUpperCase()}</span><span>{user.email}<small>{user.role}</small></span><button className="ghost" onClick={signOut}>Sign out</button></div> : <span className="api-state">● {health?.status === "ok" ? "API online" : "Connecting"}</span>}
      </header>
      {!user ? <section className="login-panel"><div className="login-copy"><span className="eyebrow">SECURE ACCESS</span><h2>Sign in to your workspace</h2><p>Access is scoped to your organization. Ask your platform administrator to provision an account.</p></div>
        <form className="login-form" onSubmit={signIn}><label>Tenant ID<input value={tenantId} onChange={e=>setTenantId(e.target.value)} required placeholder="your-organization" /></label><label>Work email<input type="email" value={email} onChange={e=>setEmail(e.target.value)} required placeholder="name@company.com" /></label><label>Password<input type="password" value={password} onChange={e=>setPassword(e.target.value)} required /></label><button className="primary" disabled={busy}>{busy ? "Signing in…" : "Sign in securely"} <span>→</span></button></form>
      </section> : <>
        <div className="welcome-row"><div><span className="eyebrow">TENANT WORKSPACE</span><h2>Welcome back</h2><p>Evidence-backed inventory starts with accurate component metadata.</p></div><div className="tenant-tag">TENANT <strong>{user.tenantId}</strong></div></div>
        <section className="metrics">
          <article className="metric-card"><span>SBOM RECORDS</span><strong>{sboms.length}</strong><small>Tenant inventory entries</small></article>
          <article className="metric-card"><span>DECLARED COMPONENTS</span><strong>{totalComponents.toLocaleString()}</strong><small>Across saved metadata</small></article>
          <article className="metric-card"><span>DATABASE</span><strong className="small-value">{health?.database ?? "unknown"}</strong><small>API connection status</small></article>
        </section>
        <section className="work-grid">
          <article className="panel"><div className="panel-head"><div><span className="eyebrow">INVENTORY INTAKE</span><h3>Add SBOM metadata</h3></div><span className="pill">Metadata only</span></div>
            <div className="sbom-form" style={{ marginBottom: 18 }}>
              <label>Upload CycloneDX / SPDX JSON (max 2 MiB)<input type="file" accept=".json,application/json" onChange={uploadSbomDocument} disabled={busy} /></label>
              <small style={{ color: "#8195a9", lineHeight: 1.5 }}>JSON documents are normalized on intake. Raw SBOM content is not retained.</small>
            </div>
            <form className="sbom-form" onSubmit={submitSbom}>
              <label>Document name<input required maxLength={200} value={form.documentName} onChange={e=>setForm({...form,documentName:e.target.value})} placeholder="payments-service" /></label>
              <div className="two-col"><label>Format<select value={form.format} onChange={e=>setForm({...form,format:e.target.value})}><option value="cyclonedx">CycloneDX</option><option value="spdx">SPDX</option></select></label><label>Format version<input required value={form.formatVersion} onChange={e=>setForm({...form,formatVersion:e.target.value})} /></label></div>
              <div className="two-col"><label>Document version<input value={form.documentVersion} onChange={e=>setForm({...form,documentVersion:e.target.value})} placeholder="1.0.0" /></label><label>Component count<input type="number" min="0" max="1000000" value={form.componentCount} onChange={e=>setForm({...form,componentCount:e.target.value})} /></label></div>
              <label>SHA-256 digest (optional)<input value={form.documentDigest} onChange={e=>setForm({...form,documentDigest:e.target.value.trim().toLowerCase()})} pattern="[a-fA-F0-9]{64}" maxLength={64} placeholder="64-character SHA-256 hex digest" /></label>
              <button className="primary" disabled={busy}>{busy ? "Saving…" : "Save metadata"} <span>＋</span></button>
            </form>
          </article>
          <article className="panel"><div className="panel-head"><div><span className="eyebrow">RECENT ACTIVITY</span><h3>SBOM inventory</h3></div><div className="inventory-actions"><button className="ghost" onClick={()=>refresh(token, search, formatFilter)}>Search ↻</button><button className="ghost" onClick={exportCsv}>Export CSV ↓</button></div></div>
            <div className="inventory-filters"><input aria-label="Search SBOM documents" placeholder="Search document names…" value={search} onChange={e=>setSearch(e.target.value)} /><select aria-label="Filter SBOM format" value={formatFilter} onChange={e=>setFormatFilter(e.target.value)}><option value="">All formats</option><option value="cyclonedx">CycloneDX</option><option value="spdx">SPDX</option></select></div>
            {sboms.length ? <div className="table-wrap"><table><thead><tr><th>DOCUMENT</th><th>FORMAT</th><th>COMPONENTS</th><th>STATUS</th><th>SECURITY</th></tr></thead><tbody>{sboms.map(item=><tr key={item._id}><td><strong>{item.documentName}</strong><small>{item.documentVersion || "No version"} · {new Date(item.createdAt).toLocaleDateString()}</small></td><td>{item.format.toUpperCase()}</td><td>{item.componentCount.toLocaleString()}</td><td><span className="status-pill">{item.ingestionStatus}</span></td><td><button className="ghost" disabled={busy} onClick={()=>scanSbom(item._id)}>Scan OSV ↗</button></td></tr>)}</tbody></table></div> : <div className="empty"><span>▤</span><strong>No SBOM metadata yet</strong><p>Save your first record to populate this tenant-scoped inventory.</p></div>}
          </article>
        </section>
        <section className="security-grid">
          <article className="panel">
            <div className="panel-head"><div><span className="eyebrow">VULNERABILITY INTELLIGENCE</span><h3>Latest OSV scan</h3></div><span className="pill">{latestScan ? latestScan.findingCount + " findings" : "No scan selected"}</span></div>
            {latestScan ? <>
              <div className="scan-summary">
                <div><strong>{latestScan.scannedPackages}</strong><small>Packages scanned</small></div>
                <div><strong>{latestScan.vulnerablePackages}</strong><small>Vulnerable packages</small></div>
                <div><strong>{latestScan.findingCount}</strong><small>Advisories</small></div>
              </div>
              <p className="scan-meta">SBOM {selectedSbom.slice(-8)} · {new Date(latestScan.scannedAt).toLocaleString()}</p>
              {latestScan.findings.length ? <div className="finding-list">{latestScan.findings.map((finding,index)=><div className="finding" key={finding.id + finding.purl + index}>
                <div className="finding-title"><strong>{finding.id}</strong><span className={"severity " + finding.severity}>{finding.severity}</span>{finding.isKnownExploited && <span className="kev">CISA KEV</span>}</div>
                <p>{finding.summary || "No advisory summary provided."}</p>
                <small>{finding.purl}</small>
                <div className="finding-metrics"><span>CVSS <b>{finding.cvssScore?.toFixed(1) ?? "—"}</b></span><span>EPSS <b>{finding.epssScore !== undefined ? (finding.epssScore * 100).toFixed(1) + "%" : "—"}</b></span><span>Percentile <b>{finding.epssPercentile !== undefined ? (finding.epssPercentile * 100).toFixed(1) + "%" : "—"}</b></span></div>
                {finding.references[0] && <a href={finding.references[0]} target="_blank" rel="noreferrer">Advisory reference ↗</a>}
              </div>)}</div> : <div className="empty"><strong>No known vulnerabilities returned</strong><p>OSV did not report findings for the scanned package URLs.</p></div>}
            </> : <div className="empty"><span>⌖</span><strong>Run a scan from SBOM inventory</strong><p>Choose “Scan OSV” on a tenant-owned SBOM to view advisories, CVSS, EPSS and CISA KEV context.</p></div>}
          </article>
          <article className="panel">
            <div className="panel-head"><div><span className="eyebrow">SUPPLY CHAIN TRUST</span><h3>Verification audit history</h3></div><button className="ghost" onClick={()=>refresh(token,search,formatFilter)}>Refresh ↻</button></div>
            {verificationHistory.length ? <div className="audit-list">{verificationHistory.map(item=><div className="audit-row" key={item._id}>
              <div><strong>{item.verificationType === "sigstore-slsa-provenance" ? "SLSA provenance" : "Artifact signature"}</strong><small>{item.certificateIdentity || item.builderId || item.failureCode || item.artifactDigest.slice(0,16)}</small><small>{new Date(item.createdAt).toLocaleString()}</small></div>
              <span className={"audit-status " + item.status}>{item.status}</span>
            </div>)}</div> : <div className="empty"><span>⌁</span><strong>No verification events yet</strong><p>Verified and rejected artifact checks will appear here.</p></div>}
            <p className="scan-meta">History is restricted to the authenticated tenant. Artifact bytes and signature bundles are never displayed.</p>
          </article>
        </section>
      </>}
      {notice && <div className="notice" role="status">{notice}</div>}
      <footer>CHAINPROOF · SECURITY OPERATIONS <span>OSV, CISA KEV, EPSS and Sigstore evidence · tenant-scoped</span></footer>
    </section>
  </main>;
}