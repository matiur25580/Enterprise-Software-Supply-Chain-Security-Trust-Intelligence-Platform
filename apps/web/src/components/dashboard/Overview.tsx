import {
  ArrowRight, ArrowUpRight, Check, ChevronDown, CircleDot,
  ExternalLink, FileCheck2, GitBranch, ShieldAlert, ShieldCheck,
  TriangleAlert
} from "lucide-react";
import { MetricCard } from "./MetricCard";

const findings = [
  { name: "openssl", version: "3.0.12", project: "payments-api", severity: "Critical", cve: "CVE-2025-15467", age: "2h ago" },
  { name: "lodash", version: "4.17.20", project: "customer-portal", severity: "High", cve: "CVE-2025-1321", age: "5h ago" },
  { name: "axios", version: "1.6.2", project: "payments-api", severity: "High", cve: "CVE-2025-27152", age: "Yesterday" },
  { name: "minimatch", version: "3.1.1", project: "data-pipeline", severity: "Medium", cve: "CVE-2024-4067", age: "Yesterday" }
];

const activities = [
  { icon: ShieldCheck, tone: "green", title: "Release policy passed", detail: "payments-api · v2.8.1", time: "12 min ago" },
  { icon: GitBranch, tone: "blue", title: "Repository connected", detail: "customer-portal · GitHub", time: "48 min ago" },
  { icon: FileCheck2, tone: "violet", title: "SBOM imported", detail: "data-pipeline · CycloneDX", time: "2 hours ago" }
];

export function Overview({ search }: { search: string }) {
  const visibleFindings = findings.filter((finding) =>
    [finding.name, finding.project, finding.severity, finding.cve].some((value) => value.toLowerCase().includes(search.toLowerCase()))
  );
  return (
    <div className="dashboard-content">
      <div className="welcome-row">
        <div><div className="eyebrow-light"><span className="live-dot" /> SECURITY POSTURE <span className="eyebrow-divider">/</span> DEMO WORKSPACE</div><h1>Good morning, team <span>✳</span></h1><p>Here’s the latest view of your software supply chain health.</p></div>
        <div className="welcome-actions"><button className="secondary-button"><Clock3 size={15} /> Last 30 days <ChevronDown size={14} /></button><button className="primary-button"><GitBranch size={15} /> Connect repository</button></div>
      </div>
      <section className="metrics-grid" aria-label="Security posture metrics">
        <MetricCard label="Security score" value="87" unit="/100" detail="vs. previous period" trend="+4.8%" icon={ShieldCheck} tone="green" points="2,27 18,21 31,24 45,13 59,17 74,8 98,5" />
        <MetricCard label="Components tracked" value="12,486" detail="across 18 projects" trend="+12.4%" icon={GitBranch} tone="blue" points="2,25 17,20 30,22 43,13 58,16 72,8 98,4" />
        <MetricCard label="Open vulnerabilities" value="24" detail="6 require immediate action" trend="-18.2%" positive={false} icon={ShieldAlert} tone="amber" points="2,5 17,10 30,8 44,17 58,13 73,24 98,28" />
        <MetricCard label="Verified releases" value="96.4%" detail="of production deployments" trend="+2.1%" icon={FileCheck2} tone="violet" points="2,26 18,21 31,23 45,15 59,17 74,8 98,4" />
      </section>
      <section className="main-panels">
        <article className="panel posture-panel">
          <div className="panel-heading"><div><h2>Risk exposure</h2><p>Vulnerability distribution across your portfolio</p></div><button className="more-button">Last 30 days <ChevronDown size={14} /></button></div>
          <div className="risk-content">
            <div className="donut-wrap"><div className="donut-chart"><div className="donut-center"><strong>24</strong><small>OPEN ISSUES</small></div></div></div>
            <div className="risk-legend">
              <div><span className="legend-dot critical" /><span>Critical</span><strong>3</strong><small>12.5%</small></div>
              <div><span className="legend-dot high" /><span>High</span><strong>8</strong><small>33.3%</small></div>
              <div><span className="legend-dot medium" /><span>Medium</span><strong>9</strong><small>37.5%</small></div>
              <div><span className="legend-dot low" /><span>Low</span><strong>4</strong><small>16.7%</small></div>
            </div>
          </div>
          <div className="panel-note"><span><Check size={14} /> 82% of your components have no known critical exposure</span><ArrowRight size={15} /></div>
        </article>
        <article className="panel trend-panel">
          <div className="panel-heading"><div><h2>Security posture trend</h2><p>Risk score over time · higher is better</p></div><button className="more-button">Weekly <ChevronDown size={14} /></button></div>
          <div className="chart-legend"><span><i className="legend-line score" /> Security score</span><span><i className="legend-line baseline" /> Industry baseline</span></div>
          <div className="line-chart">
            <div className="chart-y-labels"><span>100</span><span>75</span><span>50</span><span>25</span><span>0</span></div>
            <svg viewBox="0 0 560 180" preserveAspectRatio="none" role="img" aria-label="Security score increased from 68 to 87 over the last eight weeks">
              <defs><linearGradient id="scoreFill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#3478f6" stopOpacity=".18" /><stop offset="100%" stopColor="#3478f6" stopOpacity="0" /></linearGradient></defs>
              {[12,51,90,129,168].map(y => <line key={y} x1="0" x2="560" y1={y} y2={y} className="chart-gridline" />)}
              <path d="M0 112 C35 106 42 120 80 101 S130 92 160 96 S210 76 240 83 S290 69 320 72 S370 53 400 60 S450 39 480 45 S530 26 560 30 L560 168 L0 168Z" fill="url(#scoreFill)" />
              <path d="M0 112 C35 106 42 120 80 101 S130 92 160 96 S210 76 240 83 S290 69 320 72 S370 53 400 60 S450 39 480 45 S530 26 560 30" className="score-path" />
              <path d="M0 91 C70 90 90 89 160 86 S250 83 320 80 S430 78 560 73" className="baseline-path" />
              <circle cx="560" cy="30" r="4.5" className="chart-point" />
            </svg>
          </div>
          <div className="chart-x-labels"><span>Oct 06</span><span>Oct 13</span><span>Oct 20</span><span>Oct 27</span><span>Nov 03</span><span>Nov 10</span><span>Nov 17</span><span>Nov 22</span></div>
        </article>
      </section>
      <section className="bottom-panels">
        <article className="panel findings-panel">
          <div className="panel-heading"><div><h2>Priority findings <span className="count-pill">24</span></h2><p>Issues that need your attention</p></div><button className="text-link">View all findings <ArrowUpRight size={14} /></button></div>
          <div className="table-wrap"><table className="findings-table"><thead><tr><th>COMPONENT</th><th>PROJECT</th><th>SEVERITY</th><th>IDENTIFIER</th><th>DETECTED</th><th /></tr></thead><tbody>
            {visibleFindings.map((finding) => <tr key={finding.cve}><td><strong>{finding.name}</strong><small>v{finding.version}</small></td><td><span className="project-tag">{finding.project}</span></td><td><span className={`severity ${finding.severity.toLowerCase()}`}><i />{finding.severity}</span></td><td className="cve-id">{finding.cve}</td><td className="muted-cell">{finding.age}</td><td><button className="row-action" aria-label={`Open ${finding.cve}`}><ExternalLink size={14} /></button></td></tr>)}
            {visibleFindings.length === 0 && <tr><td colSpan={6} className="empty-state">No findings match “{search}”.</td></tr>}
          </tbody></table></div>
          <div className="table-footer"><span>Showing {visibleFindings.length} of 24 findings</span><button className="text-link">Explore vulnerability center <ArrowRight size={14} /></button></div>
        </article>
        <article className="panel activity-panel">
          <div className="panel-heading"><div><h2>Recent activity</h2><p>Latest events across your workspace</p></div><button className="more-button">All activity <ArrowUpRight size={14} /></button></div>
          <div className="activity-list">{activities.map(({ icon: Icon, tone, title, detail, time }) => <div className="activity-item" key={title}><span className={`activity-icon ${tone}`}><Icon size={15} /></span><div className="activity-copy"><strong>{title}</strong><small>{detail}</small></div><time>{time}</time></div>)}</div>
          <div className="activity-footer"><CircleDot size={14} /> Live activity stream <span className="live-dot" /></div>
        </article>
      </section>
      <div className="demo-disclaimer"><TriangleAlert size={14} /><span>Preview environment · Metrics and findings shown here are illustrative sample data, not live security telemetry.</span></div>
    </div>
  );
}
