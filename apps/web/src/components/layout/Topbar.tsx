import { Bell, ChevronDown, Search, Sparkles } from "lucide-react";

type TopbarProps = { title: string; search: string; onSearch: (value: string) => void };
export function Topbar({ title, search, onSearch }: TopbarProps) {
  return (
    <header className="topbar">
      <div className="breadcrumb"><span>Workspace</span><b>/</b><strong>{title}</strong></div>
      <div className="topbar-actions">
        <label className="global-search"><Search size={16} /><input value={search} onChange={(event) => onSearch(event.target.value)} placeholder="Search anything..." aria-label="Search workspace" /><kbd>⌘ K</kbd></label>
        <button className="icon-button assistant-button" aria-label="AI assistant"><Sparkles size={17} /></button>
        <button className="icon-button notification-button" aria-label="Notifications"><Bell size={17} /><i /></button>
        <button className="topbar-user"><span className="profile-avatar small">MR</span><ChevronDown size={14} /></button>
      </div>
    </header>
  );
}
