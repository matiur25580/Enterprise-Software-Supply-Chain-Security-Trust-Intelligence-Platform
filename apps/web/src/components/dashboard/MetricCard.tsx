import type { LucideIcon } from "lucide-react";

type MetricCardProps = {
  label: string; value: string; detail: string; trend: string; positive?: boolean;
  icon: LucideIcon; tone: "blue" | "violet" | "amber" | "green"; points: string;
};
export function MetricCard({ label, value, detail, trend, positive = true, icon: Icon, tone, points }: MetricCardProps) {
  return (
    <article className="metric-card">
      <div className="metric-top"><span>{label}</span><span className={`metric-icon ${tone}`}><Icon size={17} /></span></div>
      <div className="metric-value-row"><strong>{value}</strong><svg className="sparkline" viewBox="0 0 100 34" role="img" aria-label={`${label} trend`}><polyline points={points} /></svg></div>
      <div className="metric-foot"><span className={positive ? "trend-up" : "trend-down"}>{trend}</span><span>{detail}</span></div>
    </article>
  );
}
