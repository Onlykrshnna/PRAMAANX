/**
 * PRAMAANX - Results Page Slim Header
 * Sticky, uncluttered navigation header with view toggle (Simple / Technical)
 * and primary action "Analyze another file", matching design reference system.
 */

import { Link, useNavigate } from 'react-router-dom';
import { ArrowLeft, FileSearch, SlidersHorizontal } from 'lucide-react';
import Button from '../common/Button';
import ThemeToggle from '../common/ThemeToggle';
import { ROUTES } from '../../utils/constants';

export default function ResultsHeader({
  fileName,
  detectedType,
  viewMode,
  onToggleViewMode,
}) {
  const navigate = useNavigate();

  return (
    <header className="sticky top-0 z-30 bg-[var(--card)]/90 backdrop-blur-md border-b border-[var(--line)] transition-colors">
      <div className="max-w-[1160px] mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-16 gap-3">
          {/* Left: Back Link & File Identity */}
          <div className="flex items-center gap-3 min-w-0">
            <Link
              to={ROUTES.ANALYZE}
              className="w-9 h-9 rounded-full border border-[var(--line)] bg-[var(--card)] text-[var(--mute)] hover:text-[var(--ink)] hover:bg-[var(--soft)] flex items-center justify-center transition-all shrink-0 cursor-pointer shadow-xs"
              title="Return to evidence intake"
              aria-label="Back to Upload"
            >
              <ArrowLeft className="w-4 h-4" />
            </Link>

            <div className="flex items-center gap-2.5 truncate">
              <span className="font-extrabold text-base sm:text-lg text-[var(--ink)] tracking-tight truncate max-w-[200px] sm:max-w-xs md:max-w-md">
                {fileName || 'Forensic Inspection Report'}
              </span>
              {detectedType && (
                <span className="font-mono text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border border-[var(--line)] bg-[var(--soft)] text-[var(--brand)] shrink-0">
                  {detectedType}
                </span>
              )}
            </div>
          </div>

          {/* Right: View Toggle (Simple / Technical) & Primary Action */}
          <div className="flex items-center gap-2 sm:gap-3 shrink-0">
            {/* Simple vs Technical Switcher */}
            <div
              role="group"
              aria-label="Result detail view mode"
              className="inline-flex items-center p-1 rounded-full border border-[var(--line)] bg-[var(--soft)]"
            >
              <button
                type="button"
                onClick={() => onToggleViewMode('simple')}
                className={`px-3 py-1 rounded-full text-xs font-bold transition-all cursor-pointer ${
                  viewMode === 'simple'
                    ? 'bg-[var(--card)] text-[var(--ink)] shadow-xs border border-[var(--line)]'
                    : 'text-[var(--mute)] hover:text-[var(--ink)]'
                }`}
                title="Beginner-friendly plain-English explanations"
                aria-pressed={viewMode === 'simple'}
              >
                Simple
              </button>
              <button
                type="button"
                onClick={() => onToggleViewMode('technical')}
                className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold transition-all cursor-pointer ${
                  viewMode === 'technical'
                    ? 'bg-[var(--card)] text-[var(--ink)] shadow-xs border border-[var(--line)]'
                    : 'text-[var(--mute)] hover:text-[var(--ink)]'
                }`}
                title="Deep technical offsets, hashes, and AST inspects"
                aria-pressed={viewMode === 'technical'}
              >
                <SlidersHorizontal className="w-3 h-3 hidden sm:inline" />
                Technical
              </button>
            </div>

            {/* Theme Toggle */}
            <ThemeToggle compact={true} />

            {/* Primary Action Button */}
            <Button
              variant="dark"
              size="sm"
              icon={FileSearch}
              onClick={() => navigate(ROUTES.ANALYZE)}
            >
              <span className="hidden sm:inline">Analyze another file</span>
              <span className="sm:hidden">New</span>
            </Button>
          </div>
        </div>
      </div>
    </header>
  );
}
