import {
  Activity, Boxes, Bug, ChevronDown, CircleHelp, ClipboardCheck, FileCheck2,
  GitBranch, LayoutDashboard, Settings2, ShieldCheck, Workflow, type LucideIcon
} from "lucide-react";

type SidebarProps = { activeItem: string; onNavigate: (item: string) => void };

const groups: { label: string; items: { label: string; icon: LucideIcon; badge?: string }[] }[] = [
  { label: "WORKSPACE", items: [
    { label: "Overview", icon: LayoutDashboard },
    { label: "Projects", icon: Boxes },
    { label: "Components", icon: GitBranch },
    { label: "Vulnerabilities", icon: Bug, badge: "12" }
  ]},
  { label: "ASSURANCE", items: [
    { label: "Release security", icon: ShieldCheck },
    { label: "Policies", icon: ClipboardCheck },
    { label: "Evidence vault", icon: FileCheck2 },
    { label: "Integrations", icon: Workflow }
  ]}
];

export function Sidebar({ activeItem, onNavigate }: SidebarProps) {
  return (
    <aside className="sidebar">
      <button className="brand" onClick={() => onNavigate("Overview")} aria-label="Go to overview">
        <span className="brand-symbol"><ShieldCheck size={19} strokeWidth={2.2} /></span>
        <span className="brand-name">chainproof<span>.</span><small>SECURITY INTELLIGENCE</small></span>
      </button>
      <button className="workspace-switcher">
        <span className="workspace-avatar">N</span>
        <span className="workspace-copy"><strong>Northstar Labs</strong><small>Enterprise workspace</small></span>
        <ChevronDown size={15} />
      </button>
      <div className="sidebar-scroll">
        {groups.map((group) => (
          <div className="nav-group" key={group.label}>
            <p className="nav-label">{group.label}</p>
            {group.items.map(({ label, icon: Icon, badge }) => (
              <button key={label} className={`nav-item ${activeItem === label ? "active" : ""}`} onClick={() => onNavigate(label)}>
                <Icon size={17} strokeWidth={1.8} />
                <span>{label}</span>
                {badge && <em>{badge}</em>}
              </button>
            ))}
          </div>
        ))}
        <div className="nav-group">
          <p className="nav-label">SYSTEM</p>
          <button className={`nav-item ${activeItem === "Activity" ? "active" : ""}`} onClick={() => onNavigate("Activity")}><Activity size={17} /><span>Activity log</span></button>
          <button className={`nav-item ${activeItem === "Settings" ? "active" : ""}`} onClick={() => onNavigate("Settings")}><Settings2 size={17} /><span>Settings</span></button>
        </div>
      </div>
      <div className="sidebar-bottom">
        <div className="help-card"><span className="help-icon"><CircleHelp size={16} /></span><div><strong>Need a hand?</strong><small>Visit the knowledge base</small></div></div>
        <div className="sidebar-profile"><div className="profile-avatar">MR</div><div className="profile-copy"><strong>Workspace admin</strong><small>Platform owner</small></div><button aria-label="Profile settings"><Settings2 size={16} /></button></div>
      </div>
    </aside>
  );
}
