/**
 * PRAMAANX - Batch Navigation Sub-Bar
 * Displayed when viewing an individual forensic report within a batch.
 * Provides instant "Back to Batch", Prev/Next switcher, and direct file jump selector.
 */

import { ArrowLeft, ChevronLeft, ChevronRight, Layers } from 'lucide-react';
import Button from '../common/Button';

export default function BatchNavHeader({
  currentIndex,
  totalFiles,
  currentFileName,
  currentRiskScore,
  batchResults = [],
  onSelectIndex,
  onBackToBatch,
}) {
  const hasPrev = currentIndex > 0;
  const hasNext = currentIndex < totalFiles - 1;

  return (
    <div className="p-4 rounded-[22px] bg-[var(--card)] border border-[var(--line)] shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-3">
      {/* 1. Back to Batch Action */}
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          icon={ArrowLeft}
          onClick={onBackToBatch}
        >
          Back to Batch Overview
        </Button>
      </div>

      {/* 2. File Switcher (Prev, Selector Dropdown, Next) */}
      <div className="flex items-center gap-2 justify-center flex-1 max-w-lg">
        <Button
          variant="ghost"
          size="sm"
          icon={ChevronLeft}
          disabled={!hasPrev}
          onClick={() => hasPrev && onSelectIndex(currentIndex - 1)}
          aria-label="Previous batch file"
        />

        <div className="relative flex items-center">
          <select
            value={currentIndex}
            onChange={(e) => onSelectIndex(Number(e.target.value))}
            className="text-xs font-bold font-sans bg-[var(--soft)] text-[var(--ink)] border border-[var(--line)] rounded-full py-1.5 pl-3.5 pr-8 appearance-none cursor-pointer hover:border-[var(--brand)] focus:outline-none focus:ring-1 focus:ring-[var(--brand)] max-w-[280px] sm:max-w-[340px] truncate"
            aria-label="Select batch file to inspect"
          >
            {batchResults.map((item, idx) => {
              const score = item.analysis?.risk_score ?? '--';
              const status = item.status === 'success' ? `${score}/100` : 'Failed';
              return (
                <option key={idx} value={idx}>
                  File {idx + 1} of {totalFiles}: {item.filename} ({status})
                </option>
              );
            })}
          </select>
          <Layers className="w-3.5 h-3.5 text-[var(--mute)] absolute right-3 pointer-events-none" />
        </div>

        <Button
          variant="ghost"
          size="sm"
          icon={ChevronRight}
          disabled={!hasNext}
          onClick={() => hasNext && onSelectIndex(currentIndex + 1)}
          aria-label="Next batch file"
        />
      </div>

      {/* 3. Quick Status Badges */}
      <div className="flex items-center gap-2 self-end md:self-auto text-xs">
        <span
          className="px-3 py-1 rounded-full bg-[var(--soft)] text-[var(--mute)] font-medium border border-[var(--line)] truncate max-w-[180px]"
          title={currentFileName}
        >
          {currentFileName || `Item ${currentIndex + 1} of ${totalFiles}`}
        </span>
        {currentRiskScore !== null && currentRiskScore !== undefined && (
          <span
            className={`px-3 py-1 rounded-full font-bold font-mono border ${
              currentRiskScore <= 30
                ? 'bg-[var(--soft)] text-[var(--ok)] border-[var(--ok)]'
                : currentRiskScore <= 60
                ? 'bg-[var(--soft)] text-[var(--warn)] border-[var(--warn)]'
                : 'bg-[var(--soft)] text-[var(--bad)] border-[var(--bad)]'
            }`}
          >
            Risk: {currentRiskScore}/100
          </span>
        )}
      </div>
    </div>
  );
}
