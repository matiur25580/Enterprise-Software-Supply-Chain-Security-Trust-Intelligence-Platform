import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { AlertCircle, CheckCircle2, FileUp, KeyRound, LoaderCircle, LogOut, RefreshCw, ScanSearch, ShieldAlert, ShieldCheck } from "lucide-react";

type Project = { projectId: string; name: string; slug: string; status: string };
type Sbom = { sbomId: string; format: string; specVersion: string; documentName: string; documentSha256: string; componentCount: number; createdAt: string };
type Finding = { findingId: string; sbomId: string; componentName: string; componentVersion: string | null; vulnerabilityId: string; summary: string; severity: string; cvssScore: number | null; fixedVersions: string[]; recommendedAction: string; status: string };
type Session = { accessToken: string; refreshToken: string; expiresIn: number; organization: { id: string; name: string; slug: string }; user: { displayName: string; email: string } };
type Props = { page: string; hidden?: boolean };

const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") || "http://localhost:4000";

async function request<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}/api/v1${path}`, {
    ...init,
    headers: { ...(init.body instanceof FormData ? {} : { "Content-Type": "application/json" }), Authorization: `Bearer ${token}`, ...init.headers }
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { error?: { message?: string } } | null;
    throw new Error(payload?.error?.message || `Request failed (${response.status})`);
  }
  if (response.status === 204) return undefined as T;
  return await response.json() as T;
}

export function SecurityCenter({ page, hidden = false }: Props) {
  const [session, setSession] = useState<Session | null>(null);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [displayName, setDisplayName] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organizationSlug, setOrganizationSlug] = useState("");
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [sboms, setSboms] = useState<Sbom[]>([]);
  const [selectedSbom, setSelectedSbom] = useState("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [scanSummary, setScanSummary] = useState<{ scannedPackages: number; skippedPackages: number; vulnerabilityCount: number } | null>(null);

  const selectedProject = useMemo(() => projects.find((project) => project.projectId === projectId), [projects, projectId]);
  const loadProjects = useCallback(async (activeSession: Session) => {
    const result = await request<{ data: Project[] }>(`/organizations/${encodeURIComponent(activeSession.organization.id)}/projects?limit=100&status=active`, activeSession.accessToken);
    setProjects(result.data);
    setProjectId((current) => current || result.data[0]?.projectId || "");
  }, []);
  const loadProjectData = useCallback(async (activeSession: Session, activeProjectId: string) => {
    if (!activeProjectId) { setSboms([]); setFindings([]); return; }
    const org = encodeURIComponent(activeSession.organization.id), project = encodeURIComponent(activeProjectId);
    const [sbomResult, findingResult] = await Promise.all([
      request<{ data: Sbom[] }>(`/organizations/${org}/projects/${project}/sboms?limit=100`, activeSession.accessToken),
      request<{ data: Finding[] }>(`/organizations/${org}/projects/${project}/vulnerabilities?limit=100&status=open`, activeSession.accessToken)
    ]);
    setSboms(sbomResult.data);
    setFindings(findingResult.data);
    setSelectedSbom((current) => sbomResult.data.some((item) => item.sbomId === current) ? current : sbomResult.data[0]?.sbomId || "");
  }, []);

  useEffect(() => {
    if (!session) return;
    const timeout = window.setTimeout(async () => {
      try {
        const response = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refreshToken: session.refreshToken })
        });
        const payload = await response.json() as { data?: { accessToken: string; refreshToken: string; expiresIn: number } };
        if (!response.ok || !payload.data) throw new Error("Your session expired. Please sign in again.");
        setSession((current) => current ? { ...current, ...payload.data } : current);
      } catch (cause) {
        setSession(null); setProjects([]); setSboms([]); setFindings([]);
        setError(cause instanceof Error ? cause.message : "Session refresh failed. Please sign in again.");
      }
    }, Math.max(60, session.expiresIn - 180) * 1000);
    return () => window.clearTimeout(timeout);
  }, [session]);

  useEffect(() => {
    if (!session) return;
    let cancelled = false;
    setLoading(true); setError("");
    loadProjects(session).catch((cause: unknown) => { if (!cancelled) setError(cause instanceof Error ? cause.message : "Could not load projects."); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [session, loadProjects]);

  useEffect(() => {
    if (!session || !projectId) return;
    let cancelled = false;
    setLoading(true); setError("");
    loadProjectData(session, projectId).catch((cause: unknown) => { if (!cancelled) setError(cause instanceof Error ? cause.message : "Could not load project security data."); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [session, projectId, loadProjectData]);

  async function submitAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setLoading(true); setError(""); setNotice("");
    try {
      const isRegister = authMode === "register";
      const endpoint = isRegister ? "register" : "login";
      const body = isRegister ? { email, password, displayName, organizationName, organizationSlug } : { email, password, organizationSlug };
      const response = await fetch(`${API_BASE}/api/v1/auth/${endpoint}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
      });
      const payload = await response.json() as { data?: Session; error?: { message?: string } };
      if (!response.ok || !payload.data) throw new Error(payload.error?.message || (isRegister ? "Registration failed." : "Sign-in failed."));
      setSession(payload.data); setPassword("");
      setNotice(isRegister ? `Organization ${payload.data.organization.name} created.` : `Connected to ${payload.data.organization.name}.`);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Authentication failed."); }
    finally { setLoading(false); }
  }

  async function refreshData() {
    if (!session || !projectId) return;
    setLoading(true); setError("");
    try { await loadProjectData(session, projectId); setNotice("Project security data refreshed."); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Refresh failed."); }
    finally { setLoading(false); }
  }

  async function uploadSbom(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!session || !projectId || !uploadFile) return;
    setLoading(true); setError(""); setNotice("");
    try {
      const raw = await uploadFile.text();
      const parsed: unknown = JSON.parse(raw);
      const response = await fetch(`${API_BASE}/api/v1/organizations/${encodeURIComponent(session.organization.id)}/projects/${encodeURIComponent(projectId)}/sboms`, {
        method: "POST", headers: { Authorization: `Bearer ${session.accessToken}`, "Content-Type": "application/json" }, body: JSON.stringify(parsed)
      });
      const payload = await response.json() as { data?: Sbom; error?: { message?: string } };
      if (!response.ok) throw new Error(payload.error?.message || "SBOM upload failed.");
      setUploadFile(null); setNotice(`SBOM ingested: ${payload.data?.componentCount ?? 0} components.`);
      await loadProjectData(session, projectId);
      if (payload.data?.sbomId) setSelectedSbom(payload.data.sbomId);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not upload SBOM. Check that it is valid JSON."); }
    finally { setLoading(false); }
  }

  async function runScan() {
    if (!session || !projectId || !selectedSbom) return;
    setScanning(true); setError(""); setNotice(""); setScanSummary(null);
    try {
      const result = await request<{ data: { scannedPackages: number; skippedPackages: number; vulnerabilityCount: number } }>(
        `/organizations/${encodeURIComponent(session.organization.id)}/projects/${encodeURIComponent(projectId)}/sboms/${encodeURIComponent(selectedSbom)}/scan`,
        session.accessToken, { method: "POST" }
      );
      setScanSummary(result.data); setNotice("OSV vulnerability scan completed.");
      await loadProjectData(session, projectId);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Vulnerability scan failed."); }
    finally { setScanning(false); }
  }

  async function signOut() {
    if (session) { try { await request<void>("/auth/logout", session.accessToken, { method: "POST" }); } catch { /* local session is still cleared */ } }
    setSession(null); setProjects([]); setSboms([]); setFindings([]); setProjectId(""); setSelectedSbom(""); setScanSummary(null); setNotice("Signed out.");
  }

  if (hidden) return null;
  if (!session) return (
    <main className="security-workspace">
      <div className="security-heading"><div><span className="eyebrow-light">CHAINPROOF · CONNECTED SECURITY WORKSPACE</span><h1>{authMode === "register" ? "Create your organization" : "Connect your organization"}</h1><p>Securely manage project SBOMs and scan dependencies against OSV.dev.</p></div></div>
      <form className="auth-card" onSubmit={submitAuth}>
        <div className="auth-card-icon"><KeyRound size={20} /></div><h2>{authMode === "register" ? "Start a ChainProof workspace" : "Organization sign in"}</h2>
        <p>{authMode === "register" ? "Create an owner account and organization. Registration requires MongoDB transactions." : "Use your ChainProof account credentials and organization slug."}</p>
        {authMode === "register" && <>
          <label>Your name<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} autoComplete="name" minLength={2} maxLength={100} required /></label>
          <label>Organization name<input value={organizationName} onChange={(event) => setOrganizationName(event.target.value)} minLength={2} maxLength={120} required /></label>
        </>}
        <label>Email address<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="username" required /></label>
        <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete={authMode === "register" ? "new-password" : "current-password"} minLength={authMode === "register" ? 12 : 1} maxLength={128} required /></label>
        <label>Organization slug<input value={organizationSlug} onChange={(event) => setOrganizationSlug(event.target.value)} placeholder="your-organization" pattern="[a-z0-9]+(-[a-z0-9]+)*" minLength={3} maxLength={63} required /></label>
        <button className="primary-button" type="submit" disabled={loading}>{loading ? <LoaderCircle className="spin" size={15} /> : <ShieldCheck size={15} />} {authMode === "register" ? "Create secure workspace" : "Sign in securely"}</button>
        <button className="auth-mode-toggle" type="button" onClick={() => { setAuthMode((mode) => mode === "login" ? "register" : "login"); setError(""); }}>{authMode === "register" ? "Already have an account? Sign in" : "New to ChainProof? Create an organization"}</button>
        <small>Session tokens remain in this tab's memory and are rotated automatically. They are not persisted in browser storage.</small>
      </form>
      <p className="api-hint">API endpoint: {API_BASE} · Configure VITE_API_BASE_URL for your deployment.</p>
      {error && <div className="security-alert error"><AlertCircle size={15} />{error}</div>}
    </main>
  );

  const isVulnerabilityPage = page === "Vulnerabilities";
  return (
    <main className="security-workspace">
      <div className="security-heading"><div><span className="eyebrow-light">LIVE TENANT DATA · {session.organization.name.toUpperCase()}</span><h1>{isVulnerabilityPage ? "Vulnerability intelligence" : "SBOM & component inventory"}</h1><p>{isVulnerabilityPage ? "Review OSV advisories mapped to the components in your project SBOMs." : "Import CycloneDX or SPDX JSON inventories and run bounded vulnerability scans."}</p></div><button className="secondary-button" onClick={signOut}><LogOut size={14} /> Sign out</button></div>
      <section className="security-toolbar">
        <label>Project<select value={projectId} onChange={(event) => setProjectId(event.target.value)}><option value="">Select a project</option>{projects.map((project) => <option key={project.projectId} value={project.projectId}>{project.name} · {project.slug}</option>)}</select></label>
        <div className="security-toolbar-actions"><span>{selectedProject ? selectedProject.status : "No project selected"}</span><button className="secondary-button" onClick={refreshData} disabled={loading || !projectId}><RefreshCw size={14} /> Refresh</button></div>
      </section>
      {error && <div className="security-alert error"><AlertCircle size={15} />{error}</div>}
      {notice && <div className="security-alert success"><CheckCircle2 size={15} />{notice}</div>}
      {loading && <div className="security-loading"><LoaderCircle className="spin" size={17} /> Loading organization data…</div>}
      {!projects.length && !loading && <div className="security-empty"><ShieldAlert size={22} /><h2>No active projects found</h2><p>Create a project in the Projects API before uploading an SBOM.</p></div>}
      {!!selectedProject && !isVulnerabilityPage && <>
        <div className="security-grid">
          <section className="security-card">
            <div className="security-card-title"><div><FileUp size={17} /><h2>Import SBOM</h2></div><span>JSON · max 2 MB</span></div>
            <p>Upload a CycloneDX 1.x or SPDX 2.x JSON document. The API normalizes components and stores a SHA-256 digest.</p>
            <form className="upload-form" onSubmit={uploadSbom}><label className="file-picker"><input type="file" accept=".json,application/json" onChange={(event) => setUploadFile(event.target.files?.[0] ?? null)} /><FileUp size={17} /><span>{uploadFile ? uploadFile.name : "Choose SBOM JSON file"}</span></label><button className="primary-button" type="submit" disabled={!uploadFile || loading}>Upload SBOM</button></form>
          </section>
          <section className="security-card scan-card">
            <div className="security-card-title"><div><ScanSearch size={17} /><h2>OSV vulnerability scan</h2></div><span>External intelligence</span></div>
            <p>Query OSV.dev using versioned Package URLs from the selected SBOM. Components without valid PURLs are skipped.</p>
            <label>SBOM inventory<select value={selectedSbom} onChange={(event) => setSelectedSbom(event.target.value)}><option value="">Select an SBOM</option>{sboms.map((sbom) => <option key={sbom.sbomId} value={sbom.sbomId}>{sbom.documentName} · {sbom.componentCount} components</option>)}</select></label>
            <button className="primary-button" onClick={runScan} disabled={!selectedSbom || scanning || loading}>{scanning ? <LoaderCircle className="spin" size={15} /> : <ScanSearch size={15} />} Scan selected SBOM</button>
          </section>
        </div>
        {scanSummary && <div className="scan-summary"><strong>Latest scan</strong><span>{scanSummary.scannedPackages} packages queried</span><span>{scanSummary.skippedPackages} skipped</span><span>{scanSummary.vulnerabilityCount} advisory matches</span></div>}
        <section className="security-card inventory-card"><div className="security-card-title"><div><ShieldCheck size={17} /><h2>SBOM inventory</h2></div><span>{sboms.length} documents</span></div>
          {sboms.length ? <div className="security-table-wrap"><table className="security-table"><thead><tr><th>DOCUMENT</th><th>FORMAT</th><th>COMPONENTS</th><th>SHA-256</th><th>INGESTED</th></tr></thead><tbody>{sboms.map((sbom) => <tr key={sbom.sbomId}><td><strong>{sbom.documentName}</strong><small>{sbom.sbomId.slice(0, 8)}</small></td><td>{sbom.format} {sbom.specVersion}</td><td>{sbom.componentCount.toLocaleString()}</td><td><code>{sbom.documentSha256.slice(0, 16)}…</code></td><td>{new Date(sbom.createdAt).toLocaleDateString()}</td></tr>)}</tbody></table></div> : <div className="security-empty compact"><p>No SBOMs uploaded for this project yet.</p></div>}
        </section>
      </>}
      {!!selectedProject && isVulnerabilityPage && <section className="security-card inventory-card"><div className="security-card-title"><div><ShieldAlert size={17} /><h2>Open vulnerability findings</h2></div><span>{findings.length} shown · max 100</span></div>
        {findings.length ? <div className="security-table-wrap"><table className="security-table"><thead><tr><th>COMPONENT</th><th>ADVISORY</th><th>SEVERITY</th><th>CVSS</th><th>FIXED VERSION</th><th>RECOMMENDED ACTION</th></tr></thead><tbody>{findings.map((finding) => <tr key={finding.findingId}><td><strong>{finding.componentName}</strong><small>{finding.componentVersion || "version unknown"}</small></td><td><code>{finding.vulnerabilityId}</code><small>{finding.summary}</small></td><td><span className={`severity ${finding.severity}`}>{finding.severity}</span></td><td>{finding.cvssScore?.toFixed(1) ?? "—"}</td><td>{finding.fixedVersions.join(", ") || "Not specified"}</td><td className="action-cell">{finding.recommendedAction}</td></tr>)}</tbody></table></div> : <div className="security-empty compact"><ShieldCheck size={20} /><p>No open findings for this project. Upload an SBOM and run a scan to populate this view.</p></div>}
      </section>}
      <p className="security-footnote">Live data is retrieved from your authenticated ChainProof API. Vulnerability intelligence is sourced from OSV.dev; a successful scan is not a guarantee that a component is vulnerability-free.</p>
    </main>
  );
}
