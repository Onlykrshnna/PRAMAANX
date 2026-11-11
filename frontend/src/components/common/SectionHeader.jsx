/**
 * PRAMAANX - Architectural Section Header
 * Minimal, disciplined technical section divider with index prefix (e.g. "01 //") and optional actions.
 */

export default function SectionHeader({
  index,
  title,
  subtitle,
  action,
  className = '',
}) {
  return (
    <div className={`flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-4 border-b border-[var(--border-hairline)] ${className}`}>
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-xs font-mono font-semibold uppercase tracking-wider text-[var(--accent-cobalt)]">
          {index && <span>{index}</span>}
          {index && <span className="text-[var(--text-muted)]">//</span>}
          <span>SECTION</span>
        </div>
        <h2 className="text-2xl sm:text-3xl font-display font-bold tracking-tight text-[var(--text-primary)]">
          {title}
        </h2>
        {subtitle && (
          <p className="text-xs sm:text-sm text-[var(--text-secondary)] max-w-xl">
            {subtitle}
          </p>
        )}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

