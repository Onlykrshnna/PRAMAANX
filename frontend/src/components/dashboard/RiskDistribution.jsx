/**
 * PRAMAANX - Risk Distribution Card (Light SaaS Theme)
 * Visualizes forensic threat classification breakdown with restrained status bars.
 */

import Card from '../common/Card';
import Badge from '../common/Badge';
import { ShieldCheck, AlertTriangle, ShieldAlert, PieChart } from 'lucide-react';

export default function RiskDistribution({
  lowCount = 68,
  mediumCount = 24,
  highCount = 12,
  isDemo = true,
}) {
  const total = lowCount + mediumCount + highCount || 1;
  const lowPercent = Math.round((lowCount / total) * 100);
  const mediumPercent = Math.round((mediumCount / total) * 100);
  const highPercent = 100 - lowPercent - mediumPercent;

  return (
    <Card
      title="Threat Classification Distribution"
      subtitle="Categorized breakdown of analyzed evidence"
      headerIcon={PieChart}
      headerBadge={
        isDemo ? (
          <Badge variant="demo" size="sm">
            DEMO DATA
          </Badge>
        ) : null
      }
    >
      <div className="space-y-4">
        <div>
          <div className="flex items-center justify-between text-xs text-[var(--text-muted)] mb-2 font-mono">
            <span>Overall Risk Spread</span>
            <span>{total} Total Records</span>
          </div>

          <div className="h-3 w-full bg-[var(--bg-subtle)] rounded-full overflow-hidden flex border border-[var(--border-hairline)]">
            <div
              style={{ width: `${lowPercent}%` }}
              className="bg-[#15803D] transition-all duration-500"
              title={`Low Risk: ${lowCount} (${lowPercent}%)`}
            />
            <div
              style={{ width: `${mediumPercent}%` }}
              className="bg-[#B45309] transition-all duration-500"
              title={`Medium Risk: ${mediumCount} (${mediumPercent}%)`}
            />
            <div
              style={{ width: `${highPercent}%` }}
              className="bg-[#B91C1C] transition-all duration-500"
              title={`High Risk: ${highCount} (${highPercent}%)`}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
          {/* Low Risk */}
          <div className="p-3.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <div className="flex items-center justify-between">
              <span className="text-xs text-[var(--text-muted)] flex items-center gap-1.5 font-medium">
                <ShieldCheck className="w-4 h-4 text-[var(--status-low)]" />
                Low Risk
              </span>
              <span className="text-xs font-mono font-bold text-[var(--status-low)]">
                {lowPercent}%
              </span>
            </div>
            <div className="text-lg font-bold font-mono text-[var(--text-primary)] mt-1">
              {lowCount}
            </div>
            <span className="text-[11px] text-[var(--text-muted)]">Score 0–30</span>
          </div>

          {/* Medium Risk */}
          <div className="p-3.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <div className="flex items-center justify-between">
              <span className="text-xs text-[var(--text-muted)] flex items-center gap-1.5 font-medium">
                <AlertTriangle className="w-4 h-4 text-[var(--status-medium)]" />
                Medium Risk
              </span>
              <span className="text-xs font-mono font-bold text-[var(--status-medium)]">
                {mediumPercent}%
              </span>
            </div>
            <div className="text-lg font-bold font-mono text-[var(--text-primary)] mt-1">
              {mediumCount}
            </div>
            <span className="text-[11px] text-[var(--text-muted)]">Score 31–69</span>
          </div>

          {/* High Risk */}
          <div className="p-3.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <div className="flex items-center justify-between">
              <span className="text-xs text-[var(--text-muted)] flex items-center gap-1.5 font-medium">
                <ShieldAlert className="w-4 h-4 text-[var(--status-high)]" />
                High Risk
              </span>
              <span className="text-xs font-mono font-bold text-[var(--status-high)]">
                {highPercent}%
              </span>
            </div>
            <div className="text-lg font-bold font-mono text-[var(--text-primary)] mt-1">
              {highCount}
            </div>
            <span className="text-[11px] text-[var(--text-muted)]">Score 70–100</span>
          </div>
        </div>
      </div>
    </Card>
  );
}
