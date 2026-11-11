/**
 * PRAMAANX - Batch Overview Component
 * Renders batch summary metric ribbon (6 metrics) and clean result cards per file
 * with primary "OPEN FULL REPORT" action for each successfully examined item.
 */

import { useState } from 'react';
import {
  FileText,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ArrowRight,
  HelpCircle,
  FileSearch,
} from 'lucide-react';
import Button from '../common/Button';
import Card from '../common/Card';
import Modal from '../common/Modal';
import { formatBytes } from '../../utils/formatters';
import { getPlainEnglishVerdict } from '../../utils/explainabilityHelpers';

export default function BatchOverview({
  summary,
  results = [],
  onOpenReport,
}) {
  const [selectedError, setSelectedError] = useState(null);

  // Derived Batch Statistics
  const totalFiles = summary?.total_files ?? results.length;
  const completedCount = summary?.successful_analyses ?? results.filter((r) => r.status === 'success').length;
  const failedCount = summary?.failed_analyses ?? results.filter((r) => r.status === 'failed').length;
  const highestRisk = summary?.highest_risk_score ?? Math.max(0, ...results.map((r) => r.analysis?.risk_score || 0));
  const averageRisk = summary?.average_risk_score ?? (
    completedCount > 0
      ? (results.reduce((acc, r) => acc + (r.analysis?.risk_score || 0), 0) / completedCount).toFixed(1)
      : 0
  );

  // Files requiring human review: risk > 30, verdict is not 'no_signs', or flagged indicators present
  const filesRequiringReview = results.filter((r) => {
    if (r.status !== 'success' || !r.analysis) return false;
    const isElevated = (r.analysis.risk_score || 0) > 30;
    const isNonCleanVerdict = r.analysis.verdict && r.analysis.verdict !== 'no_signs';
    const hasFindings = (r.analysis.findings || []).length > 0;
    return isElevated || isNonCleanVerdict || hasFindings;
  }).length;

  return (
    <div className="space-y-8">
      {/* 1. Batch-Level Metric Ribbon (6 Metrics) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
        {/* Total Files */}
        <div className="p-4 rounded-[22px] border border-[var(--line)] bg-[var(--card)] shadow-xs">
          <span className="text-[11px] font-sans font-medium text-[var(--mute)] block">Total files</span>
          <span className="font-extrabold text-2xl text-[var(--ink)] mt-1 block font-sans">
            {totalFiles}
          </span>
        </div>

        {/* Completed Analyses */}
        <div className="p-4 rounded-[22px] border border-[var(--line)] bg-[var(--card)] shadow-xs">
          <span className="text-[11px] font-sans font-medium text-[var(--mute)] block">Completed</span>
          <span className="font-extrabold text-2xl text-[var(--ok)] mt-1 block font-sans">
            {completedCount}
          </span>
        </div>

        {/* Failed Analyses */}
        <div className="p-4 rounded-[22px] border border-[var(--line)] bg-[var(--card)] shadow-xs">
          <span className="text-[11px] font-sans font-medium text-[var(--mute)] block">Failed</span>
          <span
            className={`font-extrabold text-2xl mt-1 block font-sans ${
              failedCount > 0 ? 'text-[var(--bad)]' : 'text-[var(--mute)]'
            }`}
          >
            {failedCount}
          </span>
        </div>

        {/* Highest Risk */}
        <div className="p-4 rounded-[22px] border border-[var(--line)] bg-[var(--card)] shadow-xs">
          <span className="text-[11px] font-sans font-medium text-[var(--mute)] block">Highest risk</span>
          <span
            className={`font-extrabold text-2xl mt-1 block font-mono ${
              highestRisk > 60
                ? 'text-[var(--bad)]'
                : highestRisk > 30
                ? 'text-[var(--warn)]'
                : 'text-[var(--ok)]'
            }`}
          >
            {highestRisk}/100
          </span>
        </div>

        {/* Average Risk */}
        <div className="p-4 rounded-[22px] border border-[var(--line)] bg-[var(--card)] shadow-xs">
          <span className="text-[11px] font-sans font-medium text-[var(--mute)] block">Average risk</span>
          <span className="font-extrabold text-2xl text-[var(--ink)] mt-1 block font-mono">
            {averageRisk}
          </span>
        </div>

        {/* Files Requiring Review */}
        <div className="p-4 rounded-[22px] border border-[var(--line)] bg-[var(--card)] shadow-xs">
          <span className="text-[11px] font-sans font-medium text-[var(--mute)] block">Requires review</span>
          <span
            className={`font-extrabold text-2xl mt-1 block font-sans ${
              filesRequiringReview > 0 ? 'text-[var(--warn)]' : 'text-[var(--ink)]'
            }`}
          >
            {filesRequiringReview}
          </span>
        </div>
      </div>

      {/* 2. Result Cards for Each File */}
      <Card
        title="Batch File Results Inventory"
        subtitle={`${completedCount} of ${totalFiles} specimens successfully examined with full multi-engine depth`}
        headerIcon={FileSearch}
      >
        <div className="space-y-3.5">
          {results.map((item, idx) => {
            const isSuccess = item.status === 'success' && !!item.analysis;
            const fileInfo = item.file || {};
            const analysis = item.analysis || {};
            const findings = analysis.findings || [];
            const indicatorCount = findings.length;

            // Derived Verdict Presentation
            const verdictInfo = isSuccess
              ? getPlainEnglishVerdict(
                  analysis.risk_score,
                  analysis.risk_category,
                  findings,
                  fileInfo.detected_type,
                  analysis
                )
              : null;

            const riskScore = isSuccess ? analysis.risk_score : null;

            return (
              <div
                key={idx}
                className="p-5 rounded-[22px] border border-[var(--line)] bg-[var(--card)] hover:border-[var(--brand)]/40 transition-all shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                {/* Left: File Metadata & Identification */}
                <div className="flex items-start sm:items-center gap-3.5 min-w-0 flex-1">
                  <div className="w-10 h-10 rounded-2xl bg-[var(--soft)] border border-[var(--line)] text-[var(--brand)] flex items-center justify-center shrink-0 mt-0.5 sm:mt-0 shadow-xs">
                    <FileText className="w-5 h-5" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-extrabold text-sm text-[var(--ink)] truncate max-w-sm" title={item.filename}>
                        {item.filename}
                      </span>
                      <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-[var(--soft)] text-[var(--mute)] border border-[var(--line)] shrink-0">
                        {fileInfo.detected_type?.toUpperCase() || 'UNKNOWN'}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 mt-1 text-xs text-[var(--mute)]">
                      <span>{formatBytes(fileInfo.size_bytes || 0)}</span>
                      <span>•</span>
                      {fileInfo.sha256 ? (
                        <span className="font-mono text-[11px] truncate max-w-[140px] sm:max-w-[200px]" title={fileInfo.sha256}>
                          SHA: {fileInfo.sha256.slice(0, 12)}…
                        </span>
                      ) : (
                        <span>Fingerprint unavailable</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Center: Status, Verdict & Indicators */}
                <div className="flex flex-wrap items-center gap-3 shrink-0">
                  {/* Analysis Status */}
                  {isSuccess ? (
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-[var(--soft)] text-[var(--ok)] border border-[var(--ok)]/40">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Completed</span>
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-[var(--soft)] text-[var(--bad)] border border-[var(--bad)]/40">
                      <XCircle className="w-3.5 h-3.5" />
                      <span>Failed</span>
                    </span>
                  )}

                  {/* Verdict Badge */}
                  {isSuccess && verdictInfo && (
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-bold border ${
                        analysis.risk_score > 60
                          ? 'bg-[var(--soft)] text-[var(--bad)] border-[var(--bad)]'
                          : analysis.risk_score > 30
                          ? 'bg-[var(--soft)] text-[var(--warn)] border-[var(--warn)]'
                          : 'bg-[var(--soft)] text-[var(--ok)] border-[var(--ok)]'
                      }`}
                    >
                      {verdictInfo.badgeLabel || 'NO SIGNS OF EDITING'}
                    </span>
                  )}

                  {/* Indicator Count */}
                  {isSuccess && (
                    <span className="text-xs text-[var(--mute)] font-medium">
                      {indicatorCount === 0 ? (
                        '0 indicators'
                      ) : (
                        <span className="text-[var(--warn)] font-bold">
                          {indicatorCount} {indicatorCount === 1 ? 'indicator' : 'indicators'}
                        </span>
                      )}
                    </span>
                  )}
                </div>

                {/* Right: Risk Score & Action */}
                <div className="flex items-center justify-between md:justify-end gap-3.5 pt-3 md:pt-0 border-t md:border-t-0 border-[var(--line)] shrink-0">
                  <div className="text-left md:text-right">
                    <span className="text-[10px] text-[var(--mute)] block font-medium">Risk Score</span>
                    {isSuccess ? (
                      <span
                        className={`font-extrabold text-base font-mono block ${
                          riskScore > 60
                            ? 'text-[var(--bad)]'
                            : riskScore > 30
                            ? 'text-[var(--warn)]'
                            : 'text-[var(--ok)]'
                        }`}
                      >
                        {riskScore}/100
                      </span>
                    ) : (
                      <span className="text-xs text-[var(--mute)] italic block">
                        Unavailable
                      </span>
                    )}
                  </div>

                  {/* Primary "Open Full Report" Action */}
                  {isSuccess ? (
                    <Button
                      variant="primary"
                      size="sm"
                      icon={ArrowRight}
                      onClick={() => onOpenReport(idx)}
                    >
                      Open Full Report
                    </Button>
                  ) : (
                    <Button
                      variant="outline"
                      size="sm"
                      icon={AlertTriangle}
                      onClick={() =>
                        setSelectedError({
                          filename: item.filename,
                          error: item.error,
                        })
                      }
                    >
                      View Failure
                    </Button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      {/* Failure Details Modal */}
      {selectedError && (
        <Modal
          isOpen={Boolean(selectedError)}
          onClose={() => setSelectedError(null)}
          title="Analysis Failure Details"
          subtitle={`Error encountered during automated examination of ${selectedError.filename}`}
          maxWidth="max-w-lg"
        >
          <div className="space-y-4 text-xs">
            <div className="p-4 rounded-2xl bg-[var(--soft)] border border-[var(--line)] space-y-2">
              <div className="flex items-center gap-2 text-[var(--bad)] font-bold">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>Error Code: {selectedError.error?.code || 'PROCESSING_FAILED'}</span>
              </div>
              <p className="text-[var(--ink)] leading-relaxed">
                {selectedError.error?.message ||
                  'The forensic pipeline was unable to safely process this specimen. Verify that the file is not corrupted, password-protected, or of an unsupported container format.'}
              </p>
            </div>

            <div className="p-4 rounded-2xl bg-[var(--card)] border border-[var(--line)] space-y-2 text-[var(--mute)]">
              <div className="flex items-center gap-2 font-bold text-[var(--ink)]">
                <HelpCircle className="w-4 h-4 text-[var(--brand)]" />
                <span>Safety & Isolation Guarantee</span>
              </div>
              <p className="leading-relaxed">
                PRAMAANX isolates each file analysis in an independent sandbox task. A parsing failure in this item did not degrade or halt the examination of other files in this batch.
              </p>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
