import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { AlertCircle, Archive, Boxes, CheckCircle2, ExternalLink, FolderPlus, GitBranch, LoaderCircle, LogOut, Pencil, RefreshCw, Search, ShieldCheck } from "lucide-react";

type Project = {
  projectId: string; name: string; slug: string; description: string; repositoryUrl: string;
  defaultBranch: string; status: "active" | "archived"; createdAt: string; updatedAt: string;
};
type RepositoryLink = {
  repositoryId: number; fullName: string; htmlUrl: string; defaultBranch: string;
  isPrivate: boolean; status: "active" | "suspended" | "removed"; installationId: number;
  syncStatus?: "never" | "syncing" | "succeeded" | "failed"; lastSyncedAt?: string | null; lastSyncedCommitSha?: string | null; lastSyncedCommitAt?: string | null; syncError?: string | null;
};
type Session = {
  accessToken: string; refreshToken: string; expiresIn: number;
  organization: { id: string; name: string; slug: string };
  user: { displayName: string; email: string };
};
type ProjectForm = { name: string; slug: string; description: string; repositoryUrl: string; defaultBranch: string };
type Installation = { installationId: number; accountLogin?: string; accountType?: string; repositorySelection?: string; status: "pending_verification" | "active" | "suspended" | "removed"; verifiedAt?: string | null };
type ProviderRepository = { id: number; name: string; full_name: string; html_url: string; default_branch: string; private: boolean };
const API_BASE = (import.meta.env.VITE_API_BASE_URL as string | undefined)?.replace(/\/$/, "") || "http://localhost:4000";
const emptyForm: ProjectForm = { name: "", slug: "", description: "", repositoryUrl: "https://github.com/", defaultBranch: "main" };

async function api<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}/api/v1${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, ...init.headers }
  });
  const payload = await response.json().catch(() => null) as { data?: T; error?: { message?: string } } | null;
  if (!response.ok) throw new Error(payload?.error?.message || `Request failed (${response.status})`);
  return payload?.data as T;
}

export function ProjectRegistry({ hidden = false }: { hidden?: boolean }) {
  const [session, setSession] = useState<Session | null>(null);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [displayName, setDisplayName] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organizationSlug, setOrganizationSlug] = useState("");
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [links, setLinks] = useState<RepositoryLink[]>([]);
  const [installations, setInstallations] = useState<Installation[]>([]);
  const [providerRepositories, setProviderRepositories] = useState<ProviderRepository[]>([]);
  const [selectedInstallation, setSelectedInstallation] = useState("");
  const [selectedRepository, setSelectedRepository] = useState("");
  const [form, setForm] = useState<ProjectForm>(emptyForm);
  const [editing, setEditing] = useState(false);
  const [creating, setCreating] = useState(false);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<"all" | "active" | "archived">("active");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const selected = useMemo(() => projects.find((item) => item.projectId === selectedId), [projects, selectedId]);
  const visibleProjects = useMemo(() => projects.filter((item) =>
    (status === "all" || item.status === status) &&
    `${item.name} ${item.slug} ${item.repositoryUrl}`.toLowerCase().includes(query.toLowerCase())
  ), [projects, query, status]);

  const loadProjects = useCallback(async (active: Session) => {
    const org = encodeURIComponent(active.organization.id);
    const [activeResult, archivedResult] = await Promise.all([
      api<Project[]>(`/organizations/${org}/projects?limit=100&status=active`, active.accessToken),
      api<Project[]>(`/organizations/${org}/projects?limit=100&status=archived`, active.accessToken)
    ]);
    const all = [...activeResult, ...archivedResult].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    setProjects(all);
    setSelectedId((current) => all.some((item) => item.projectId === current) ? current : all.find((item) => item.status === "active")?.projectId || all[0]?.projectId || "");
  }, []);

  const loadInstallations = useCallback(async (active: Session) => {
    const org = encodeURIComponent(active.organization.id);
    const result = await api<Installation[]>(`/integrations/github/organizations/${org}/installations`, active.accessToken);
    setInstallations(result);
    setSelectedInstallation((current) => result.some((item) => String(item.installationId) === current && item.status === "active") ? current : String(result.find((item) => item.status === "active")?.installationId || ""));
  }, []);

  const loadLinks = useCallback(async (active: Session, projectId: string) => {
    if (!projectId) { setLinks([]); return; }
    const org = encodeURIComponent(active.organization.id), project = encodeURIComponent(projectId);
    const result = await api<RepositoryLink[]>(`/integrations/github/organizations/${org}/projects/${project}/repositories`, active.accessToken);
    setLinks(result);
  }, []);

  const refresh = useCallback(async () => {
    if (!session) return;
    setLoading(true); setError("");
    try {
      await loadProjects(session);
      if (selectedId) await loadLinks(session, selectedId);
      setNotice("Project registry refreshed.");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not refresh the project registry."); }
    finally { setLoading(false); }
  }, [session, selectedId, loadProjects, loadLinks, loadInstallations]);

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
        setSession(null); setProjects([]); setLinks([]);
        setError(cause instanceof Error ? cause.message : "Session refresh failed.");
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
  }, [session, loadProjects, loadInstallations]);

  useEffect(() => {
    if (!session || !selectedId) { setLinks([]); return; }
    let cancelled = false;
    loadLinks(session, selectedId).catch((cause: unknown) => { if (!cancelled) setError(cause instanceof Error ? cause.message : "Could not load repository links."); });
    return () => { cancelled = true; };
  }, [session, selectedId, loadLinks]);

  async function submitAuth(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setLoading(true); setError(""); setNotice("");
    try {
      const registering = authMode === "register";
      const body = registering ? { email, password, displayName, organizationName, organizationSlug } : { email, password, organizationSlug };
      const response = await fetch(`${API_BASE}/api/v1/auth/${registering ? "register" : "login"}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body)
      });
      const payload = await response.json() as { data?: Session; error?: { message?: string } };
      if (!response.ok || !payload.data) throw new Error(payload.error?.message || "Authentication failed.");
      setSession(payload.data); setPassword("");
      setNotice(registering ? "Organization workspace created." : `Connected to ${payload.data.organization.name}.`);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Authentication failed."); }
    finally { setLoading(false); }
  }

  function startCreate() {
    setCreating(true); setEditing(false); setForm(emptyForm); setError(""); setNotice("");
  }
  function startEdit() {
    if (!selected) return;
    setEditing(true); setCreating(false);
    setForm({ name: selected.name, slug: selected.slug, description: selected.description || "", repositoryUrl: selected.repositoryUrl, defaultBranch: selected.defaultBranch });
    setError(""); setNotice("");
  }

  async function saveProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!session) return;
    setSaving(true); setError(""); setNotice("");
    try {
      const org = encodeURIComponent(session.organization.id);
      const payload = creating
        ? await api<Project>(`/organizations/${org}/projects`, session.accessToken, { method: "POST", body: JSON.stringify(form) })
        : await api<Project>(`/organizations/${org}/projects/${encodeURIComponent(selectedId)}`, session.accessToken, {
            method: "PATCH", body: JSON.stringify({ name: form.name, description: form.description, repositoryUrl: form.repositoryUrl, defaultBranch: form.defaultBranch })
          });
      await loadProjects(session);
      setSelectedId(payload.projectId);
      setCreating(false); setEditing(false);
      setNotice(creating ? "Project created successfully." : "Project details saved.");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not save project."); }
    finally { setSaving(false); }
  }

  async function archiveProject() {
    if (!session || !selected || selected.status === "archived") return;
    if (!window.confirm(`Archive project “${selected.name}”? It will remain available in the archived filter.`)) return;
    setSaving(true); setError(""); setNotice("");
    try {
      const org = encodeURIComponent(session.organization.id);
      await api<Project>(`/organizations/${org}/projects/${encodeURIComponent(selected.projectId)}`, session.accessToken, {
        method: "PATCH", body: JSON.stringify({ status: "archived" })
      });
      await loadProjects(session);
      setNotice("Project archived. Its inventory and audit history are retained.");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not archive project."); }
    finally { setSaving(false); }
  }


  async function discoverRepositorySboms(repositoryId: number) {
    if (!session || !selected) return;
    setSaving(true); setError(""); setNotice("");
    try {
      const org = encodeURIComponent(session.organization.id), project = encodeURIComponent(selected.projectId);
      const result = await api<{ fullName: string; commitSha: string; candidateCount: number; downloadedCount: number; ingested: Array<{ sbomId: string; path: string; componentCount: number }>; duplicates: Array<{ path: string }>; skippedCount: number; skipped: Array<{ path: string; reason: string }> }>(`/integrations/github/organizations/${org}/projects/${project}/repositories/${repositoryId}/sbom-discovery`, session.accessToken, { method: "POST" });
      await loadLinks(session, selected.projectId);
      const details = result.ingested.map((item) => `${item.path} (${item.componentCount} components)`).join(", ");
      setNotice(`SBOM discovery on ${result.fullName}: ${result.ingested.length} ingested, ${result.duplicates.length} already present, ${result.skippedCount} skipped. ${details}`);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "SBOM discovery failed."); }
    finally { setSaving(false); }
  }

  async function syncRepository(repositoryId: number) {
    if (!session || !selected) return;
    setSaving(true); setError(""); setNotice("");
    try {
      const org = encodeURIComponent(session.organization.id), project = encodeURIComponent(selected.projectId);
      const result = await api<{ fullName: string; defaultBranch: string; lastSyncedCommitSha: string; syncStatus: string }>(`/integrations/github/organizations/${org}/projects/${project}/repositories/${repositoryId}/sync`, session.accessToken, { method: "POST" });
      await loadLinks(session, selected.projectId);
      setNotice(`Synced ${result.fullName} · ${result.defaultBranch} · ${result.lastSyncedCommitSha.slice(0, 12)}.`);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Repository sync failed."); await loadLinks(session, selected.projectId).catch(() => undefined); }
    finally { setSaving(false); }
  }

  async function connectGitHubApp() {
    if (!session) return;
    setError(""); setNotice("");
    try {
      const org = encodeURIComponent(session.organization.id);
      const result = await api<{ installUrl: string }>(`/integrations/github/organizations/${org}/installations/start`, session.accessToken, { method: "POST" });
      window.open(result.installUrl, "_blank", "noopener,noreferrer");
      setNotice("GitHub App installation opened. Complete the provider flow, then refresh this workspace.");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not start GitHub App installation."); }
  }

  async function verifyInstallation(installationId: number) {
    if (!session) return;
    setSaving(true); setError(""); setNotice("");
    try {
      const org = encodeURIComponent(session.organization.id);
      await api(`/integrations/github/organizations/${org}/installations/${installationId}/verify`, session.accessToken, { method: "POST" });
      await loadInstallations(session);
      setSelectedInstallation(String(installationId));
      setNotice("GitHub App installation verified with read-only repository permissions.");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Installation verification failed."); }
    finally { setSaving(false); }
  }

  async function discoverRepositories() {
    if (!session || !selectedInstallation) return;
    setSaving(true); setError(""); setProviderRepositories([]);
    try {
      const org = encodeURIComponent(session.organization.id);
      const result = await api<{ repositories: ProviderRepository[] }>(`/integrations/github/organizations/${org}/installations/${selectedInstallation}/repositories`, session.accessToken);
      setProviderRepositories(result.repositories);
      setSelectedRepository("");
      setNotice(`Discovered ${result.repositories.length} repositories from GitHub.`);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Repository discovery failed."); }
    finally { setSaving(false); }
  }

  async function linkSelectedRepository() {
    if (!session || !selected || !selectedInstallation || !selectedRepository) return;
    setSaving(true); setError(""); setNotice("");
    try {
      const org = encodeURIComponent(session.organization.id), project = encodeURIComponent(selected.projectId);
      await api(`/integrations/github/organizations/${org}/projects/${project}/repositories`, session.accessToken, {
        method: "POST", body: JSON.stringify({ installationId: Number(selectedInstallation), repositoryId: Number(selectedRepository) })
      });
      await loadLinks(session, selected.projectId);
      setProviderRepositories([]);
      setNotice("Repository linked using provider-verified GitHub metadata.");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not link repository."); }
    finally { setSaving(false); }
  }

  async function signOut() {
    if (session) { try { await api<void>("/auth/logout", session.accessToken, { method: "POST" }); } catch { /* clear local state even if the network is unavailable */ } }
    setSession(null); setProjects([]); setLinks([]); setSelectedId(""); setNotice("Signed out.");
  }

  if (hidden) return null;
  if (!session) return (
    <main className="project-workspace">
      <div className="project-heading"><div><span className="eyebrow-light">CHAINPROOF · PROJECT REGISTRY</span><h1>Connect your organization</h1><p>Manage tenant-owned software projects and their source repository metadata.</p></div></div>
      <form className="auth-card" onSubmit={submitAuth}>
        <div className="auth-card-icon"><ShieldCheck size={20} /></div><h2>{authMode === "register" ? "Create a workspace" : "Organization sign in"}</h2>
        <p>{authMode === "register" ? "Create an owner account and organization. MongoDB transactions must be enabled." : "Sign in with your ChainProof account and organization slug."}</p>
        {authMode === "register" && <><label>Your name<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} minLength={2} maxLength={100} required /></label><label>Organization name<input value={organizationName} onChange={(event) => setOrganizationName(event.target.value)} minLength={2} maxLength={120} required /></label></>}
        <label>Email address<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label>
        <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} minLength={authMode === "register" ? 12 : 1} maxLength={128} required /></label>
        <label>Organization slug<input value={organizationSlug} onChange={(event) => setOrganizationSlug(event.target.value)} pattern="[a-z0-9]+(-[a-z0-9]+)*" minLength={3} maxLength={63} placeholder="your-organization" required /></label>
        <button className="primary-button" type="submit" disabled={loading}>{loading ? <LoaderCircle className="spin" size={15} /> : <ShieldCheck size={15} />}{authMode === "register" ? "Create secure workspace" : "Sign in securely"}</button>
        <button className="auth-mode-toggle" type="button" onClick={() => { setAuthMode((mode) => mode === "login" ? "register" : "login"); setError(""); }}>{authMode === "register" ? "Already registered? Sign in" : "New to ChainProof? Create an organization"}</button>
        <small>Tokens stay in this tab's memory and refresh automatically; they are not written to browser storage.</small>
      </form>
      {error && <div className="security-alert error"><AlertCircle size={15} />{error}</div>}
    </main>
  );

  return (
    <main className="project-workspace">
      <header className="project-heading">
        <div><span className="eyebrow-light">LIVE TENANT DATA · {session.organization.name.toUpperCase()}</span><h1>Project registry</h1><p>Own the software projects that anchor SBOMs, vulnerability findings, and repository connections.</p></div>
        <div className="project-heading-actions"><button className="secondary-button" onClick={refresh} disabled={loading}><RefreshCw size={14} /> Refresh</button><button className="secondary-button" onClick={signOut}><LogOut size={14} /> Sign out</button></div>
      </header>
      {error && <div className="security-alert error"><AlertCircle size={15} />{error}</div>}
      {notice && <div className="security-alert success"><CheckCircle2 size={15} />{notice}</div>}
      <section className="project-toolbar">
        <label className="project-search"><Search size={15} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search projects, slugs, repositories…" /></label>
        <select value={status} onChange={(event) => setStatus(event.target.value as typeof status)} aria-label="Project status"><option value="active">Active projects</option><option value="archived">Archived projects</option><option value="all">All projects</option></select>
        <button className="primary-button" onClick={startCreate}><FolderPlus size={15} /> New project</button>
      </section>
      {loading && <div className="security-loading"><LoaderCircle className="spin" size={16} /> Loading tenant projects…</div>}
      <div className="project-layout">
        <section className="project-list-card">
          <div className="project-list-header"><div><Boxes size={16} /><strong>Projects</strong></div><span>{visibleProjects.length} shown</span></div>
          {visibleProjects.length ? visibleProjects.map((project) => (
            <button key={project.projectId} className={`project-list-item ${selectedId === project.projectId ? "selected" : ""}`} onClick={() => { setSelectedId(project.projectId); setCreating(false); setEditing(false); }}>
              <span className="project-list-icon"><GitBranch size={16} /></span><span className="project-list-copy"><strong>{project.name}</strong><small>{project.slug} · {project.defaultBranch}</small></span><span className={`project-status ${project.status}`}>{project.status}</span>
            </button>
          )) : <div className="security-empty compact"><p>{loading ? "Loading projects…" : "No projects match this filter. Create a project to get started."}</p></div>}
        </section>
        <section className="project-detail-card">
          {(creating || editing) ? (
            <>
              <div className="project-detail-heading"><div><span className="eyebrow-light">{creating ? "NEW TENANT PROJECT" : "EDIT PROJECT"}</span><h2>{creating ? "Create project" : "Update project details"}</h2></div></div>
              <form className="project-form" onSubmit={saveProject}>
                <label>Project name<input value={form.name} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} minLength={2} maxLength={120} required /></label>
                <label>Project slug<input value={form.slug} onChange={(event) => setForm((current) => ({ ...current, slug: event.target.value.toLowerCase().replace(/\s+/g, "-") }))} pattern="[a-z0-9]+(-[a-z0-9]+)*" minLength={2} maxLength={63} disabled={!creating} required /><small>Unique within this organization; immutable after creation.</small></label>
                <label>Repository URL<input type="url" value={form.repositoryUrl} onChange={(event) => setForm((current) => ({ ...current, repositoryUrl: event.target.value }))} placeholder="https://github.com/acme/service" required /></label>
                <label>Default branch<input value={form.defaultBranch} onChange={(event) => setForm((current) => ({ ...current, defaultBranch: event.target.value }))} maxLength={255} required /></label>
                <label className="project-description-field">Description<textarea value={form.description} onChange={(event) => setForm((current) => ({ ...current, description: event.target.value }))} maxLength={1000} rows={4} /></label>
                <div className="project-form-actions"><button className="secondary-button" type="button" onClick={() => { setCreating(false); setEditing(false); }}>Cancel</button><button className="primary-button" type="submit" disabled={saving}>{saving ? <LoaderCircle className="spin" size={14} /> : <CheckCircle2 size={14} />}{creating ? "Create project" : "Save changes"}</button></div>
              </form>
            </>
          ) : selected ? (
            <>
              <div className="project-detail-heading"><div><span className="eyebrow-light">PROJECT DETAILS</span><h2>{selected.name}</h2><p>{selected.description || "No project description has been added."}</p></div><span className={`project-status large ${selected.status}`}>{selected.status}</span></div>
              <div className="project-detail-actions"><button className="secondary-button" onClick={startEdit}><Pencil size={14} /> Edit details</button>{selected.status === "active" && <button className="secondary-button danger-action" onClick={archiveProject} disabled={saving}><Archive size={14} /> Archive</button>}</div>
              <div className="project-facts">
                <div><small>PROJECT SLUG</small><strong>{selected.slug}</strong></div>
                <div><small>DEFAULT BRANCH</small><strong>{selected.defaultBranch}</strong></div>
                <div><small>LAST UPDATED</small><strong>{new Date(selected.updatedAt).toLocaleString()}</strong></div>
                <div><small>CREATED</small><strong>{new Date(selected.createdAt).toLocaleDateString()}</strong></div>
              </div>
              <div className="project-repository"><div><GitBranch size={16} /><strong>Source repository</strong></div><a href={selected.repositoryUrl} target="_blank" rel="noreferrer">{selected.repositoryUrl}<ExternalLink size={13} /></a></div>
              <div className="project-repository linked-repositories"><div><ShieldCheck size={16} /><strong>Verified GitHub repository links</strong><span>{links.length}</span></div>
                {links.length ? links.map((link) => <div className="linked-repository-row" key={link.repositoryId}><span><strong>{link.fullName}</strong><small>Repository ID {link.repositoryId} · {link.isPrivate ? "Private" : "Public"} · {link.defaultBranch}</small></span><span className={`project-status ${link.status === "active" ? "active" : "archived"}`}>{link.status}</span><span className="repository-sync-state">{link.syncStatus || "never"}{link.lastSyncedCommitSha ? ` · ${link.lastSyncedCommitSha.slice(0, 8)}` : ""}</span>{link.status === "active" && <><button className="secondary-button" disabled={saving} onClick={() => syncRepository(link.repositoryId)}>Sync now</button><button className="secondary-button" disabled={saving} onClick={() => discoverRepositorySboms(link.repositoryId)}>Discover SBOMs</button></>}<a href={link.htmlUrl} target="_blank" rel="noreferrer" aria-label={`Open ${link.fullName}`}><ExternalLink size={13} /></a></div>) : <p>No GitHub App repository is linked to this project. Provider linking requires an owner/admin to install and verify the ChainProof GitHub App.</p>}
              </div>
              <div className="project-repository github-connect-panel">
                <div><ShieldCheck size={16} /><strong>GitHub App connection</strong><span>{installations.length} installation(s)</span></div>
                <p>Install the ChainProof GitHub App, verify its identity and discover repositories using read-only Contents and Metadata permissions.</p>
                <div className="github-connect-actions">
                  <button className="secondary-button" onClick={connectGitHubApp}>Install GitHub App</button>
                  <button className="secondary-button" onClick={() => loadInstallations(session).catch((cause: unknown) => setError(cause instanceof Error ? cause.message : "Could not refresh installations."))}>Refresh installations</button>
                </div>
                {installations.map((item) => <div className="github-install-row" key={item.installationId}>
                  <span><strong>{item.accountLogin || `Installation #${item.installationId}`}</strong><small>#{item.installationId} · {item.repositorySelection || "selection pending"} · {item.status}</small></span>
                  {item.status === "pending_verification" && <button className="secondary-button" disabled={saving} onClick={() => verifyInstallation(item.installationId)}>Verify</button>}
                  {item.status === "active" && <span className="project-status active">verified</span>}
                </div>)}
                {installations.some((item) => item.status === "active") && <>
                  <label className="github-select-label">Verified installation
                    <select value={selectedInstallation} onChange={(event) => { setSelectedInstallation(event.target.value); setProviderRepositories([]); }}>
                      {installations.filter((item) => item.status === "active").map((item) => <option key={item.installationId} value={item.installationId}>{item.accountLogin || item.installationId}</option>)}
                    </select>
                  </label>
                  <button className="secondary-button" disabled={!selectedInstallation || saving} onClick={discoverRepositories}><RefreshCw size={13}/> Discover available repositories</button>
                  {providerRepositories.length > 0 && <div className="github-repository-picker">
                    <label className="github-select-label">Repository to link
                      <select value={selectedRepository} onChange={(event) => setSelectedRepository(event.target.value)}>
                        <option value="">Choose a GitHub repository</option>
                        {providerRepositories.map((item) => <option key={item.id} value={item.id}>{item.full_name}{item.private ? " · private" : ""}</option>)}
                      </select>
                    </label>
                    <button className="primary-button" disabled={!selectedRepository || saving || selected.status !== "active"} onClick={linkSelectedRepository}>Link to this project</button>
                  </div>}
                </>}
                {installations.length === 0 && <p>No GitHub App installation is registered for this organization yet.</p>}
              </div>
              <p className="project-security-note">Organization ownership is derived from the authenticated session. The browser cannot assign a project to another tenant.</p>
            </>
          ) : <div className="security-empty"><Boxes size={22} /><h2>Select a project</h2><p>Choose a project from the list or create your first project to begin organizing software supply-chain evidence.</p><button className="primary-button" onClick={startCreate}><FolderPlus size={14} /> Create project</button></div>}
        </section>
      </div>
      <p className="security-footnote">Project records and repository links are retrieved from the authenticated ChainProof API. Archived projects remain visible and retain their associated evidence.</p>
    </main>
  );
}
