/**
 * PRAMAANX - Results Metadata Tab
 * Clean, structured presentation:
 * - "Found" metadata rows displayed cleanly.
 * - Replaces useless missing rows with JPEG structure analysis.
 * - If 5 or more EXIF fields are absent:
 *   - Simple view: one line only ("Shared via messaging app, likely recompressed.")
 *   - Technical view / details: shows estimated quality, recompression level, saving software fingerprint,
 *     full table, marker order, and quantization hash.
 * - Missing metadata collapsed, filename never used as evidence.
 * - Expandable technical raw JSON drawer.
 * Follows design reference system tokens, rounded-[26px] cards, and Manrope typography.
 */

import { useState } from 'react';
import { ChevronDown, ChevronUp, FileCode, Clock, Cpu, Sliders, ShieldAlert } from 'lucide-react';
import { sanitizeMetadataValue } from '../../utils/metadataHelpers';

export default function MetadataTab({
  metadataReport,
  jpegStructure,
  viewMode = 'simple', // 'simple' | 'technical'
}) {
  const [showMissing, setShowMissing] = useState(false);
  const [showRawPayload, setShowRawPayload] = useState(false);
  const [showTechStructure, setShowTechStructure] = useState(false);

  if (!metadataReport || !metadataReport.fields) {
    return (
      <div className="p-8 text-center text-sm font-sans text-[var(--mute)]">
        No container metadata extracted from this specimen.
      </div>
    );
  }

  const foundFields = metadataReport.fields.filter((f) => f.status === 'Available');
  const missingFields = metadataReport.fields.filter(
    (f) => f.status === 'Missing' || f.status === 'Not examined'
  );
  const unreadableFields = metadataReport.fields.filter((f) => f.status === 'Unreadable');

  const isHighMissing = missingFields.length >= 5;
  const struct = jpegStructure || metadataReport.rawMetadata?.jpeg_structure;

  return (
    <div className="space-y-6">
      {/* Overview Metric Ribbon */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        <div className="p-4 rounded-[22px] border border-[var(--line)] bg-[var(--card)] shadow-xs">
          <span className="text-xs font-medium text-[var(--mute)] block">Examined</span>
          <span className="font-extrabold text-xl text-[var(--ink)] block mt-0.5">
            {metadataReport.overview?.totalExamined || metadataReport.fields.length}
          </span>
        </div>

        <div className="p-4 rounded-[22px] border border-[var(--ok)]/40 bg-[var(--soft)] shadow-xs">
          <span className="text-xs font-bold text-[var(--ok)] block">Present</span>
          <span className="font-extrabold text-xl text-[var(--ok)] block mt-0.5">
            {foundFields.length}
          </span>
        </div>

        <div className="p-4 rounded-[22px] border border-[var(--line)] bg-[var(--card)] shadow-xs">
          <span className="text-xs font-medium text-[var(--mute)] block">Absent</span>
          <span className="font-extrabold text-xl text-[var(--mute)] block mt-0.5">
            {missingFields.length}
          </span>
        </div>

        <div className="p-4 rounded-[22px] border border-[var(--line)] bg-[var(--card)] shadow-xs">
          <span className="text-xs font-medium text-[var(--mute)] block">Unreadable</span>
          <span className="font-extrabold text-xl text-[var(--ink)] block mt-0.5">
            {unreadableFields.length}
          </span>
        </div>
      </div>

      {/* Messaging App & Missing EXIF Replacement Card */}
      {isHighMissing && struct && (
        <div className="p-5 sm:p-6 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-4 shadow-xs">
          {viewMode === 'simple' ? (
            <div className="flex items-center gap-3 text-sm font-bold text-[var(--ink)]">
              <span className="w-2.5 h-2.5 rounded-full bg-[var(--warn)]" />
              <span>Shared via messaging app, likely recompressed.</span>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="flex items-start gap-3">
                <div className="w-9 h-9 rounded-full bg-[var(--soft)] flex items-center justify-center text-[var(--warn)] shrink-0 mt-0.5">
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <div>
                  <h4 className="font-extrabold text-base text-[var(--ink)] tracking-tight">
                    Original camera data is gone. This image was likely shared through a messaging app.
                  </h4>
                  <p className="text-xs text-[var(--mute)] mt-1">
                    Here is what we can still tell you from the low-level JPEG structure:
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
                <div className="p-3.5 rounded-2xl bg-[var(--soft)]/50 border border-[var(--line)]">
                  <span className="text-xs text-[var(--mute)] block">Estimated quality</span>
                  <span className="font-bold text-sm text-[var(--ink)] mt-0.5 block font-mono">
                    {struct.estimated_quality !== null && struct.estimated_quality !== undefined
                      ? `${struct.estimated_quality} / 100`
                      : 'Non-standard tables'}
                  </span>
                </div>

                <div className="p-3.5 rounded-2xl bg-[var(--soft)]/50 border border-[var(--line)]">
                  <span className="text-xs text-[var(--mute)] block">Recompression level</span>
                  <span className="font-bold text-sm text-[var(--warn)] mt-0.5 block">
                    {struct.likely_messaging_app_recompression
                      ? 'Likely recompressed'
                      : 'Standard compression'}
                  </span>
                </div>

                <div className="p-3.5 rounded-2xl bg-[var(--soft)]/50 border border-[var(--line)]">
                  <span className="text-xs text-[var(--mute)] block">Saving software / DQT fingerprint</span>
                  <span className="font-bold text-xs text-[var(--ink)] truncate block mt-0.5 font-mono" title={struct.quantization_tables_hash}>
                    {struct.quantization_tables_hash ? `Hash: ${struct.quantization_tables_hash.slice(0, 16)}...` : 'Standard IJG'}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Technical View: Full JPEG Structure Telemetry */}
      {struct && (viewMode === 'technical' || showTechStructure) && (
        <div className="rounded-[26px] border border-[var(--line)] bg-[var(--card)] overflow-hidden shadow-xs">
          <div className="p-5 border-b border-[var(--line)] bg-[var(--soft)]/30 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Cpu className="w-4 h-4 text-[var(--brand)]" />
              <h4 className="font-extrabold text-sm text-[var(--ink)] tracking-tight">
                JPEG physical structure & marker sequence
              </h4>
            </div>
            <span className="font-mono text-xs text-[var(--mute)]">
              {struct.encoding} • {struct.chroma_subsampling}
            </span>
          </div>

          <div className="p-5 space-y-4 text-xs font-mono">
            {/* Markers Sequence */}
            <div>
              <span className="text-xs font-sans text-[var(--mute)] block mb-2">
                Marker order (physical stream):
              </span>
              <div className="flex flex-wrap items-center gap-1.5">
                {struct.markers && struct.markers.length > 0 ? (
                  struct.markers.map((m, idx) => (
                    <span
                      key={idx}
                      className="px-2.5 py-1 rounded-full bg-[var(--soft)] text-xs text-[var(--ink)] border border-[var(--line)] font-bold"
                    >
                      {m}
                    </span>
                  ))
                ) : (
                  <span className="text-[var(--mute)]">Standard SOI/EOI stream</span>
                )}
              </div>
            </div>

            {/* Metrics grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-[var(--line)]">
              <div>
                <span className="text-xs font-sans text-[var(--mute)] block">Chroma subsampling</span>
                <span className="font-bold text-sm text-[var(--ink)] mt-0.5 block">{struct.chroma_subsampling}</span>
              </div>
              <div>
                <span className="text-xs font-sans text-[var(--mute)] block">Encoding</span>
                <span className="font-bold text-sm text-[var(--ink)] capitalize mt-0.5 block">{struct.encoding}</span>
              </div>
              <div>
                <span className="text-xs font-sans text-[var(--mute)] block">Bytes / pixel</span>
                <span className="font-bold text-sm text-[var(--ink)] mt-0.5 block">{struct.bytes_per_pixel} B/px</span>
              </div>
              <div>
                <span className="text-xs font-sans text-[var(--mute)] block">DQT hash</span>
                <span className="font-bold text-xs text-[var(--ink)] mt-0.5 block truncate" title={struct.quantization_tables_hash}>
                  {struct.quantization_tables_hash ? `${struct.quantization_tables_hash.slice(0, 12)}...` : 'None'}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 1. Present / Found Metadata Fields */}
      <div className="space-y-3">
        <h4 className="font-extrabold text-base text-[var(--ink)] tracking-tight pb-2 border-b border-[var(--line)]">
          Present container properties ({foundFields.length})
        </h4>

        {foundFields.length === 0 ? (
          <div className="p-6 rounded-[22px] border border-[var(--line)] bg-[var(--card)] text-sm text-[var(--mute)] text-center shadow-xs">
            No embedded container fields were discovered in this file.
          </div>
        ) : (
          <div className="divide-y divide-[var(--line)] rounded-[26px] border border-[var(--line)] bg-[var(--card)] overflow-hidden shadow-xs">
            {foundFields.map((field) => (
              <div
                key={field.id}
                className="p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:bg-[var(--soft)]/30 transition-colors"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm text-[var(--ink)] flex items-center gap-1.5">
                      {field.isTimestamp && <Clock className="w-3.5 h-3.5 text-[var(--brand)]" />}
                      <span>{field.name}</span>
                    </span>
                    {viewMode === 'technical' && field.source && (
                      <span className="font-mono text-[10px] text-[var(--mute)] bg-[var(--soft)] px-2 py-0.5 rounded-full border border-[var(--line)]">
                        {field.source}
                      </span>
                    )}
                  </div>
                  {viewMode === 'technical' && field.description && (
                    <p className="text-xs text-[var(--mute)]">{field.description}</p>
                  )}
                </div>

                <div className="font-mono text-xs font-semibold text-[var(--ink)] sm:text-right break-all max-w-sm">
                  <span
                    dangerouslySetInnerHTML={{
                      __html: sanitizeMetadataValue(field.value),
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 2. Collapsed Missing Metadata Line */}
      {missingFields.length > 0 && (
        <div className="rounded-[22px] border border-[var(--line)] bg-[var(--card)] overflow-hidden shadow-xs">
          <button
            type="button"
            onClick={() => setShowMissing((prev) => !prev)}
            className="w-full p-4 sm:p-5 flex items-center justify-between gap-3 text-left hover:bg-[var(--soft)]/40 transition-colors cursor-pointer"
          >
            <div className="space-y-0.5">
              <span className="text-xs text-[var(--mute)]">
                <strong className="text-[var(--ink)]">{missingFields.length} fields are absent.</strong>{' '}
                This is typical for images and files shared via WhatsApp, Signal, or web recompression.
              </span>
            </div>

            <div className="flex items-center gap-1.5 text-xs font-bold text-[var(--brand)] shrink-0">
              <span>{showMissing ? 'Hide list' : 'View absent fields'}</span>
              {showMissing ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </div>
          </button>

          {showMissing && (
            <div className="p-5 pt-2 border-t border-[var(--line)] space-y-2">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono text-[var(--mute)]">
                {missingFields.map((f) => (
                  <div
                    key={f.id}
                    className="p-2.5 rounded-xl bg-[var(--soft)]/50 border border-[var(--line)] flex items-center justify-between"
                  >
                    <span className="text-[var(--ink)]">{f.name}</span>
                    <span className="text-xs text-[var(--mute)] italic">Not present</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 3. Advanced Raw Metadata JSON Drawer */}
      <div className="pt-2 flex flex-wrap items-center gap-4">
        {struct && viewMode === 'simple' && (
          <button
            type="button"
            onClick={() => setShowTechStructure((prev) => !prev)}
            className="flex items-center gap-1.5 text-xs font-bold text-[var(--brand)] hover:underline cursor-pointer"
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>{showTechStructure ? 'Hide' : 'Inspect'} low-level JPEG structure</span>
          </button>
        )}

        <button
          type="button"
          onClick={() => setShowRawPayload((prev) => !prev)}
          className="flex items-center gap-2 text-xs font-bold text-[var(--mute)] hover:text-[var(--ink)] cursor-pointer"
        >
          <FileCode className="w-3.5 h-3.5 text-[var(--brand)]" />
          <span>{showRawPayload ? 'Collapse' : 'Inspect'} raw container JSON payload</span>
          {showRawPayload ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
        </button>

        {showRawPayload && (
          <pre className="w-full mt-3 p-5 rounded-[22px] bg-[var(--card)] border border-[var(--line)] text-xs font-mono text-[var(--ink)] overflow-x-auto max-h-80 leading-relaxed shadow-xs">
            {JSON.stringify(metadataReport.rawMetadata || {}, null, 2)}
          </pre>
        )}
      </div>
    </div>
  );
}
