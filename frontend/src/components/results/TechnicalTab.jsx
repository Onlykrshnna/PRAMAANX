/**
 * PRAMAANX - Results Technical Details Tab
 * Complete technical evidence archive matching design reference system:
 * - Cryptographic SHA-256 hash with copy trigger in JetBrains Mono
 * - MIME & container specifications
 * - Shannon byte entropy
 * - Full 4-state diagnostic checklist
 * - AI Model weights specifications
 * - 5-category finding taxonomy with byte offsets
 * - Raw JSON log drawer
 * Follows design tokens, rounded-[26px] cards, and Manrope/JetBrains Mono font rule.
 */

import { useState } from 'react';
import {
  Copy,
  Check,
  FileCode,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
} from 'lucide-react';
import { formatBytes } from '../../utils/formatters';

export default function TechnicalTab({
  fileInfo,
  analysis,
  examinationChecklist = [],
  findings = [],
}) {
  const [copiedHash, setCopiedHash] = useState(false);
  const [showRawJson, setShowRawJson] = useState(false);

  const hash = fileInfo?.sha256 || analysis?.sha256 || '';
  const entropy = fileInfo?.entropy || analysis?.entropy || null;

  const handleCopy = () => {
    if (!hash) return;
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const getChecklistIcon = (status) => {
    switch (status) {
      case 'Passed':
        return <CheckCircle2 className="w-4 h-4 text-[var(--ok)] shrink-0" />;
      case 'Flagged':
        return <AlertTriangle className="w-4 h-4 text-[var(--warn)] shrink-0" />;
      case 'Error':
        return <XCircle className="w-4 h-4 text-[var(--bad)] shrink-0" />;
      default:
        return <HelpCircle className="w-4 h-4 text-[var(--mute)] shrink-0" />;
    }
  };

  const getChecklistBadge = (status) => {
    switch (status) {
      case 'Passed':
        return 'text-[var(--ok)] bg-[var(--soft)] border-[var(--ok)]';
      case 'Flagged':
        return 'text-[var(--warn)] bg-[var(--soft)] border-[var(--warn)]';
      case 'Error':
        return 'text-[var(--bad)] bg-[var(--soft)] border-[var(--bad)]';
      default:
        return 'text-[var(--mute)] bg-[var(--soft)] border-[var(--line)]';
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Core Cryptographic & Container Properties */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
        {/* SHA-256 Hash Card */}
        <div className="p-5 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-2 shadow-xs sm:col-span-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-[var(--mute)]">
              Cryptographic custody hash (SHA-256)
            </span>
            <button
              type="button"
              onClick={handleCopy}
              className="flex items-center gap-1.5 text-xs font-bold text-[var(--brand)] hover:underline cursor-pointer"
            >
              {copiedHash ? <Check className="w-3.5 h-3.5 text-[var(--ok)]" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedHash ? 'Copied' : 'Copy hash'}</span>
            </button>
          </div>
          <span className="font-mono text-xs font-medium text-[var(--ink)] select-all break-all block">
            {hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
          </span>
        </div>

        {/* MIME & Type */}
        <div className="p-5 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-1 shadow-xs">
          <span className="text-xs font-semibold text-[var(--mute)]">
            Detected MIME & format
          </span>
          <span className="font-bold text-sm text-[var(--ink)] block font-mono">
            {fileInfo?.detected_mime || 'application/octet-stream'}
          </span>
          <span className="text-xs text-[var(--mute)] block">
            Container: {fileInfo?.detected_type || 'Generic Binary'}
          </span>
        </div>

        {/* Shannon Entropy */}
        <div className="p-5 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-1 shadow-xs">
          <span className="text-xs font-semibold text-[var(--mute)]">
            Shannon byte entropy
          </span>
          <span className="font-bold text-sm text-[var(--ink)] block font-mono">
            {entropy !== null ? `${entropy.toFixed(3)} bits/byte` : 'Calculated in stream'}
          </span>
          <span className="text-xs text-[var(--mute)] block">
            {entropy && entropy > 7.2
              ? 'High entropy (normal for compressed streams)'
              : 'Standard distribution'}
          </span>
        </div>

        {/* Byte Size */}
        <div className="p-5 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-1 shadow-xs">
          <span className="text-xs font-semibold text-[var(--mute)]">
            Physical payload size
          </span>
          <span className="font-bold text-sm text-[var(--ink)] block font-mono">
            {formatBytes(fileInfo?.size || 0)} ({fileInfo?.size || 0} bytes)
          </span>
        </div>

        {/* Engine Checkpoint */}
        <div className="p-5 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-1 shadow-xs">
          <span className="text-xs font-semibold text-[var(--mute)]">
            Active neural checkpoint
          </span>
          <span className="font-bold text-sm text-[var(--ink)] block font-mono">
            EfficientNet-B0 (16.3 MB)
          </span>
          <span className="text-xs text-[var(--mute)] block">
            Trained on CASIA 2.0 • 224×224 input
          </span>
        </div>
      </div>

      {/* 2. Full 4-State Forensic Checklist */}
      <div className="space-y-3 pt-2">
        <h4 className="font-extrabold text-base text-[var(--ink)] tracking-tight pb-2 border-b border-[var(--line)]">
          Automated pipeline diagnostics ({examinationChecklist.length} stages)
        </h4>

        <div className="divide-y divide-[var(--line)] rounded-[26px] border border-[var(--line)] bg-[var(--card)] overflow-hidden shadow-xs">
          {examinationChecklist.map((item, idx) => (
            <div
              key={idx}
              className="p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-[var(--soft)]/30 transition-colors"
            >
              <div className="flex items-start gap-3">
                {getChecklistIcon(item.status)}
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm text-[var(--ink)]">
                      {item.title}
                    </span>
                    <span className="text-xs font-mono text-[var(--mute)] px-2 py-0.5 rounded-full border border-[var(--line)] bg-[var(--soft)]">
                      {item.analyzerRef}
                    </span>
                  </div>
                  <p className="text-xs text-[var(--mute)] mt-1">{item.description}</p>
                </div>
              </div>

              <span
                className={`text-xs font-bold uppercase tracking-wider px-3 py-1 rounded-full border shrink-0 self-start sm:self-auto ${getChecklistBadge(
                  item.status
                )}`}
              >
                {item.status}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* 3. All Raw Findings & Byte Offsets */}
      <div className="space-y-3 pt-2">
        <h4 className="font-extrabold text-base text-[var(--ink)] tracking-tight pb-2 border-b border-[var(--line)]">
          Forensic indicators & supporting evidence ({findings.length})
        </h4>

        {findings.length === 0 ? (
          <div className="p-6 rounded-[22px] border border-[var(--line)] bg-[var(--card)] text-sm text-[var(--mute)] text-center shadow-xs">
            Zero flagged indicators. All static rules and neural inferences cleared baseline thresholds.
          </div>
        ) : (
          <div className="space-y-3">
            {findings.map((f, idx) => (
              <div
                key={idx}
                className="p-5 rounded-[22px] border border-[var(--line)] bg-[var(--card)] space-y-2.5 shadow-xs"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className="font-bold text-sm text-[var(--ink)]">
                      {f.title || f.name}
                    </span>
                    <span className="text-xs font-mono text-[var(--mute)] px-2 py-0.5 rounded-full border border-[var(--line)] bg-[var(--soft)]">
                      {f.category || 'Indicator'}
                    </span>
                  </div>
                  <span className="text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full border border-[var(--line)] bg-[var(--soft)] text-[var(--ink)]">
                    {f.severity || 'info'}
                  </span>
                </div>

                <p className="text-xs text-[var(--mute)] leading-relaxed">
                  {f.detail || f.description}
                </p>

                {/* Technical Offsets & References if available */}
                {(f.offset !== undefined || f.byte_offset || f.object_id || f.raw_evidence) && (
                  <div className="p-3 rounded-xl bg-[var(--soft)]/50 border border-[var(--line)] space-y-1 font-mono text-xs text-[var(--mute)]">
                    {f.byte_offset && <div>Offset: {f.byte_offset}</div>}
                    {f.object_id && <div>PDF Object: {f.object_id}</div>}
                    {f.raw_evidence && <div>Raw Evidence: {f.raw_evidence}</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 4. Raw JSON Payload Drawer */}
      <div className="pt-2">
        <button
          type="button"
          onClick={() => setShowRawJson((prev) => !prev)}
          className="flex items-center gap-2 text-xs font-bold text-[var(--mute)] hover:text-[var(--ink)] cursor-pointer"
        >
          <FileCode className="w-3.5 h-3.5 text-[var(--brand)]" />
          <span>{showRawJson ? 'Hide' : 'Inspect'} raw analysis JSON log</span>
          {showRawJson ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>

        {showRawJson && (
          <pre className="mt-3 p-5 rounded-[22px] bg-[var(--card)] border border-[var(--line)] text-xs font-mono text-[var(--ink)] overflow-x-auto max-h-96 leading-relaxed shadow-xs">
            {JSON.stringify({ file: fileInfo, analysis }, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}
