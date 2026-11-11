/**
 * PRAMAANX - Results Overview Tab
 * Simple, high-clarity summary matching design reference system:
 * 1. "What we found" (1-3 plain-language finding cards, each with 2 lines: "What it means" & "What you can do")
 * 2. "What this does NOT prove" evidentiary scope notice
 * Zero banned words, rounded-[26px] cards, and Manrope typography.
 */

import { AlertTriangle, AlertCircle, Info, CheckCircle2 } from 'lucide-react';

export default function OverviewTab({
  findings = [],
  _riskScore = 0,
  _fileType,
  _onNavigateTab,
}) {
  // Filter and deduplicate findings to at most 3 top actionable items
  const significantFindings = findings
    .filter((f) => f.severity === 'high' || f.severity === 'medium')
    .slice(0, 3);

  // If no medium/high findings exist, provide a clean "All Checks Cleared" card
  const isClean = significantFindings.length === 0;

  return (
    <div className="space-y-6">
      {/* 1. What We Found */}
      <div className="space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[var(--line)]">
          <div className="flex items-center gap-2">
            <h3 className="font-extrabold text-lg text-[var(--ink)] tracking-tight">
              What we found
            </h3>
            <span className="text-xs font-medium text-[var(--mute)]">
              ({isClean ? 'Clean baseline' : `${significantFindings.length} items requiring attention`})
            </span>
          </div>
        </div>

        {isClean ? (
          <div className="p-6 rounded-[26px] border border-[var(--ok)]/40 bg-[var(--soft)] flex items-start gap-4 shadow-xs">
            <div className="w-10 h-10 rounded-full bg-[var(--card)] flex items-center justify-center text-[var(--ok)] shrink-0 mt-0.5 border border-[var(--line)]">
              <CheckCircle2 className="w-5 h-5" />
            </div>
            <div className="space-y-1.5">
              <h4 className="font-extrabold text-base text-[var(--ink)] tracking-tight">
                No structural or cryptographic anomalies observed
              </h4>
              <p className="text-xs text-[var(--mute)] leading-relaxed">
                <strong className="text-[var(--ink)]">What it means:</strong> Magic byte signatures, container headers, and compression distribution match standard published format specifications.
              </p>
              <p className="text-xs text-[var(--mute)] leading-relaxed">
                <strong className="text-[var(--ink)]">What you can do:</strong> You can proceed with standard handling or generate a sealed PDF verification report for your records.
              </p>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4">
            {significantFindings.map((f, idx) => {
              const isHigh = f.severity === 'high';
              const borderClass = isHigh
                ? 'border-[var(--bad)]/40 bg-[var(--soft)]'
                : 'border-[var(--warn)]/40 bg-[var(--soft)]';
              const iconColor = isHigh ? 'text-[var(--bad)]' : 'text-[var(--warn)]';

              return (
                <div
                  key={idx}
                  className={`p-6 rounded-[26px] border ${borderClass} space-y-3 shadow-xs`}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2.5">
                      {isHigh ? (
                        <AlertCircle className={`w-5 h-5 ${iconColor} shrink-0`} />
                      ) : (
                        <AlertTriangle className={`w-5 h-5 ${iconColor} shrink-0`} />
                      )}
                      <h4 className="font-extrabold text-base text-[var(--ink)] tracking-tight">
                        {f.title || f.name}
                      </h4>
                    </div>

                    <span
                      className={`text-xs font-bold uppercase tracking-wider px-3 py-0.5 rounded-full border ${
                        isHigh
                          ? 'bg-[var(--card)] text-[var(--bad)] border-[var(--bad)]'
                          : 'bg-[var(--card)] text-[var(--warn)] border-[var(--warn)]'
                      }`}
                    >
                      {f.severity}
                    </span>
                  </div>

                  {/* Exactly Two Lines as requested */}
                  <div className="space-y-1.5 pt-1 text-xs text-[var(--mute)] leading-relaxed">
                    <p>
                      <strong className="text-[var(--ink)]">What it means: </strong>
                      {f.detail || f.description || 'Observed deviation from standard container specification.'}
                    </p>
                    <p>
                      <strong className="text-[var(--ink)]">What you can do: </strong>
                      {f.remediation || f.recommendation || 'Inspect visual heatmap or cross-verify original source timestamps.'}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 2. What This Does NOT Prove */}
      <div className="p-6 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-2.5 shadow-xs">
        <div className="flex items-center gap-2 text-xs font-bold text-[var(--brand)]">
          <Info className="w-4 h-4 shrink-0" />
          <span>Evidentiary scope: What this does NOT prove</span>
        </div>
        <p className="text-xs text-[var(--mute)] leading-relaxed">
          Automated forensic scores and AI predictions are investigative triage aids, not absolute courtroom legal proof. Missing metadata is typical on privacy-focused communication platforms (e.g. Signal, WhatsApp) and does not establish intentional modification. Local neural predictions are heuristic and require human corroboration before making definitive assessments.
        </p>
      </div>
    </div>
  );
}
