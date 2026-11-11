/**
 * PRAMAANX - Dashboard Stat Card Component (Light SaaS Theme)
 * Displays forensic metrics with clean status highlights and demo indicators.
 */

import Card from '../common/Card';
import Badge from '../common/Badge';

export default function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'neutral',
  trendText,
  isDemo = true,
  onClick,
}) {
  const accentColors = {
    neutral: 'text-[var(--text-primary)] bg-[var(--bg-subtle)] border-[var(--border-hairline)]',
    low: 'text-[var(--status-low)] bg-[var(--status-low-bg)] border-[var(--status-low-border)]',
    medium: 'text-[var(--status-medium)] bg-[var(--status-medium-bg)] border-[var(--status-medium-border)]',
    high: 'text-[var(--status-high)] bg-[var(--status-high-bg)] border-[var(--status-high-border)]',
  };

  return (
    <Card
      onClick={onClick}
      className="relative overflow-hidden transition-all hover:border-[var(--border-strong)]"
    >
      <div className="flex items-start justify-between">
        <div>
          <span className="text-xs font-medium text-[var(--text-muted)] tracking-wide uppercase">
            {title}
          </span>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="text-2xl sm:text-3xl font-bold font-mono tracking-tight text-[var(--text-primary)]">
              {value}
            </span>
            {trendText && (
              <span className="text-xs text-[var(--text-muted)] font-mono">
                {trendText}
              </span>
            )}
          </div>
          {subtitle && (
            <p className="text-xs text-[var(--text-muted)] mt-1.5 leading-normal">
              {subtitle}
            </p>
          )}
        </div>

        <div className="flex flex-col items-end gap-2">
          {Icon && (
            <div
              className={`p-2.5 rounded-xl border flex items-center justify-center ${
                accentColors[variant] || accentColors.neutral
              }`}
            >
              <Icon className="w-5 h-5" />
            </div>
          )}
          {isDemo && (
            <Badge variant="demo" size="sm">
              DEMO
            </Badge>
          )}
        </div>
      </div>
    </Card>
  );
}
