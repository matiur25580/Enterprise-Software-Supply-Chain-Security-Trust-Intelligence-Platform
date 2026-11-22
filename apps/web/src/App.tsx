import { useState } from "react";
import { ArrowLeft, Construction, ShieldCheck } from "lucide-react";
import { Sidebar } from "./components/layout/Sidebar";
import { Topbar } from "./components/layout/Topbar";
import { Overview } from "./components/dashboard/Overview";
import { SecurityCenter } from "./components/security/SecurityCenter";
import { ProjectRegistry } from "./components/projects/ProjectRegistry";

const pageDescriptions: Record<string, string> = {
  Projects: "Connect repositories and understand ownership, dependencies, and release posture.",
  Components: "Explore normalized packages, versions, licenses, and dependency relationships.",
  Vulnerabilities: "Prioritize vulnerability exposure with severity and exploitability context.",
  "Release security": "Review provenance, artifact integrity, and release trust decisions.",
  Policies: "Define deterministic security controls and release acceptance criteria.",
  "Evidence vault": "Collect traceable attestations, SBOMs, and compliance evidence.",
  Integrations: "Connect source control, registries, CI providers, and security intelligence.",
  Activity: "Review important changes and security events across your organization.",
  Settings: "Manage workspace preferences, access, and platform configuration."
};

function ComingSoon({ page, onBack }: { page: string; onBack: () => void }) {
  return <div className="coming-soon"><div className="coming-icon"><Construction size={24} /></div><span className="eyebrow-light">WORKSPACE MODULE</span><h1>{page}</h1><p>{pageDescriptions[page] ?? "This workspace module is part of the ChainProof product roadmap."}</p><div className="module-status"><ShieldCheck size={16} /> Foundation established · Implementation planned in upcoming milestones</div><button className="secondary-button" onClick={onBack}><ArrowLeft size={15} /> Back to overview</button></div>;
}

export default function App() {
  const [activeItem, setActiveItem] = useState("Overview");
  const [search, setSearch] = useState("");
  const title = activeItem === "Overview" ? "Security overview" : activeItem;
  return (
    <div className="app-shell">
      <Sidebar activeItem={activeItem} onNavigate={setActiveItem} />
      <div className="app-main">
        <Topbar title={title} search={search} onSearch={setSearch} />
        {activeItem === "Overview" ? <Overview search={search} /> : !["Projects", "Components", "Vulnerabilities"].includes(activeItem) ? <ComingSoon page={activeItem} onBack={() => setActiveItem("Overview")} /> : null}
        <ProjectRegistry hidden={activeItem !== "Projects"} />
        <SecurityCenter page={activeItem} hidden={!["Components", "Vulnerabilities"].includes(activeItem)} />
      </div>
    </div>
  );
}
