/**
 * PRAMAANX - Architectural Risk Indicator
 * Visualizes forensic threat risk (0-100) using disciplined geometric gauges,
 * calibrated probability thresholds, and zero artificial glow.
 */

import { getRiskLevel } from '../../utils/riskHelpers';

export default function RiskIndicator({
  score = 0,
  _size = 'md', // 'sm' | 'md' | 'lg'
  showBar = true,
  className = '',
}) {
  const riskInfo = getRiskLevel(score);

  const getStatusColor = (s) => {
    if (s <= 30) return 'text-[var(--status-low)] bg-[var(--status-low-bg)] border-[var(--status-low-border)]';
    if (s <= 69) return 'text-[var(--status-medium)] bg-[var(--status-medium-bg)] border-[var(--status-medium-border)]';
    return 'text-[var(--status-high)] bg-[var(--status-high-bg)] border-[var(--status-high-border)]';
  };

  const getBarColor = (s) => {
    if (s <= 30) return 'bg-[var(--status-low)]';
    if (s <= 69) return 'bg-[var(--status-medium)]';
    return 'bg-[var(--status-high)]';
  };

  return (
    <div className={`space-y-1.5 ${className}`}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-baseline gap-2">
          <span className="text-2xl sm:text-3xl font-mono font-bold tracking-tight text-[var(--text-primary)]">
            {score}
          </span>
          <span className="text-xs font-mono text-[var(--text-muted)]">/100</span>
        </div>
        <span
          className={`text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border ${getStatusColor(
            score
          )}`}
        >
          {riskInfo.label}
        </span>
      </div>

      {showBar && (
        <div className="h-2 w-full rounded-full bg-[var(--bg-subtle)] border border-[var(--border-hairline)] overflow-hidden">
          <div
            className={`h-full transition-all duration-500 ease-out ${getBarColor(score)}`}
            style={{ width: `${Math.min(Math.max(score, 0), 100)}%` }}
          />
        </div>
      )}
    </div>
  );
}
