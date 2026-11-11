/**
 * PRAMAANX - Results Visual Evidence Tab
 * Side-by-side interactive split slider between Original Specimen and Heatmap/ELA.
 * Normalization by 99th percentile, scale factor display in Technical view,
 * responsive layer alignment, and robust loading/error handling.
 */

import { useState, useMemo } from 'react';
import ImageComparisonSlider from './ImageComparisonSlider';
import { Eye, Activity, FileText, AlertCircle, AlertTriangle, ZoomIn } from 'lucide-react';

export default function VisualEvidenceTab({
  originalUrl,
  gradcamUrl,
  elaUrl,
  elaStats,
  isRecompressed = false,
  viewMode = 'simple',
  onOpenZoom,
}) {
  const [userSelectedMode, setUserSelectedMode] = useState(null);

  const availableModes = useMemo(() => {
    const modes = [];
    if (gradcamUrl) modes.push('heatmap');
    if (elaUrl) modes.push('ela');
    return modes;
  }, [gradcamUrl, elaUrl]);

  const compareMode = useMemo(() => {
    if (userSelectedMode && availableModes.includes(userSelectedMode)) {
      return userSelectedMode;
    }
    return gradcamUrl ? 'heatmap' : elaUrl ? 'ela' : 'original';
  }, [userSelectedMode, availableModes, gradcamUrl, elaUrl]);

  const hasAnyVisual = Boolean(gradcamUrl || elaUrl || originalUrl);

  if (!hasAnyVisual) {
    return (
      <div className="p-10 text-center rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-4 shadow-xs">
        <div className="w-14 h-14 rounded-2xl bg-[var(--soft)] text-[var(--brand)] flex items-center justify-center mx-auto">
          <FileText className="w-7 h-7" />
        </div>
        <h4 className="font-extrabold text-base text-[var(--ink)] tracking-tight">
          No visual evidence generated for this file type
        </h4>
        <p className="text-sm text-[var(--mute)] max-w-md mx-auto leading-relaxed">
          Computer vision heatmaps and Error Level Analysis are generated for image formats (JPEG, PNG, TIFF). Structured document containers are inspected via AST and metadata dissection.
        </p>
      </div>
    );
  }

  const activeCompareSrc = compareMode === 'heatmap' ? gradcamUrl : elaUrl;
  const isArtifactAvailable = Boolean(activeCompareSrc);

  return (
    <div className="space-y-6">
      {/* Header & Mode Switcher */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--line)]">
        <div>
          <h3 className="font-extrabold text-lg text-[var(--ink)] tracking-tight">
            Visual anomaly comparison
          </h3>
          <p className="text-xs text-[var(--mute)] mt-0.5">
            Compare the original evidence specimen against algorithmic and neural anomaly maps.
          </p>
        </div>

        {/* Toggle between Heatmap and ELA - Segmented Rounded Pill */}
        <div className="inline-flex items-center p-1 rounded-full border border-[var(--line)] bg-[var(--soft)] self-start sm:self-auto">
          {gradcamUrl && (
            <button
              type="button"
              onClick={() => setUserSelectedMode('heatmap')}
              className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-bold transition-all cursor-pointer ${
                compareMode === 'heatmap'
                  ? 'bg-[var(--card)] text-[var(--brand)] shadow-xs border border-[var(--line)]'
                  : 'text-[var(--mute)] hover:text-[var(--ink)]'
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span>AI Heatmap</span>
            </button>
          )}

          {elaUrl && (
            <button
              type="button"
              onClick={() => setUserSelectedMode('ela')}
              className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-bold transition-all cursor-pointer ${
                compareMode === 'ela'
                  ? 'bg-[var(--card)] text-[var(--warn)] shadow-xs border border-[var(--line)]'
                  : 'text-[var(--mute)] hover:text-[var(--ink)]'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Compression check (ELA)</span>
            </button>
          )}
        </div>
      </div>

      {/* Recompression Warning Caption */}
      {isRecompressed && compareMode === 'ela' && (
        <div className="p-4 rounded-2xl border border-[var(--warn)]/40 bg-[var(--soft)] text-xs text-[var(--ink)] flex items-center gap-3">
          <AlertCircle className="w-4 h-4 text-[var(--warn)] shrink-0" />
          <span className="font-medium">ELA is less reliable on recompressed images.</span>
        </div>
      )}

      {/* Main Draggable Split Slider or Specimen Canvas */}
      {isArtifactAvailable && originalUrl ? (
        <ImageComparisonSlider
          originalSrc={originalUrl}
          compareSrc={activeCompareSrc}
          originalLabel="Original specimen"
          compareLabel={
            compareMode === 'heatmap'
              ? 'AI attention heatmap'
              : 'Compression check (ELA)'
          }
          isEla={compareMode === 'ela'}
          onOpenZoom={onOpenZoom}
        />
      ) : originalUrl ? (
        <div className="relative h-[360px] sm:h-[460px] md:h-[520px] rounded-[22px] border border-[var(--line)] bg-black/95 overflow-hidden flex items-center justify-center shadow-xs">
          <img
            src={originalUrl}
            alt="Original forensic specimen"
            className="w-full h-full object-contain pointer-events-none select-none"
          />
          <div className="absolute top-3.5 left-3.5 bg-black/80 backdrop-blur-xs text-white text-xs font-bold px-3.5 py-1.5 rounded-full border border-white/20 shadow-md flex items-center gap-2 z-10">
            <span className="w-2 h-2 rounded-full bg-[var(--ok)]" />
            <span>Original specimen</span>
          </div>
          <div className="absolute bottom-3.5 left-3.5 right-3.5 sm:left-4 sm:right-auto bg-black/85 backdrop-blur-xs text-xs text-white/90 p-3.5 rounded-2xl border border-white/20 max-w-md shadow-lg z-10">
            <p className="font-bold text-white">Visual anomaly map not triggered</p>
            <p className="text-[11px] text-white/70 mt-0.5 leading-relaxed">
              No localized tampering heatmaps or compression anomalies were detected for this specimen.
            </p>
          </div>
          {onOpenZoom && (
            <button
              type="button"
              onClick={() =>
                onOpenZoom({
                  title: 'Original Evidence Specimen',
                  src: originalUrl,
                  caption: 'Original specimen submitted for forensic examination.',
                })
              }
              className="absolute bottom-3.5 right-3.5 px-3.5 py-1.5 rounded-full bg-black/80 hover:bg-black text-white text-xs font-bold border border-white/20 flex items-center gap-1.5 shadow-lg transition-colors cursor-pointer z-10"
            >
              <ZoomIn className="w-3.5 h-3.5" />
              <span>Full zoom</span>
            </button>
          )}
        </div>
      ) : (
        <div className="p-8 text-center rounded-[22px] border border-[var(--line)] bg-[var(--card)] space-y-2 shadow-xs">
          <AlertTriangle className="w-6 h-6 text-[var(--warn)] mx-auto" />
          <p className="text-xs font-bold text-[var(--ink)]">Original specimen unavailable</p>
          <p className="text-xs text-[var(--mute)] max-w-sm mx-auto">
            The visual evidence specimen could not be retrieved from storage.
          </p>
        </div>
      )}

      {/* Technical Scale Factor Display */}
      {compareMode === 'ela' && (viewMode === 'technical' || elaStats?.scale_factor) && (
        <div className="p-4 rounded-2xl border border-[var(--line)] bg-[var(--card)] text-xs font-mono text-[var(--mute)] flex flex-wrap items-center justify-between gap-3 shadow-xs">
          <span>
            <strong className="text-[var(--ink)] font-sans">Colormap:</strong> OpenCV Inferno (99th percentile scaled)
          </span>
          {elaStats?.scale_factor && (
            <span>
              <strong className="text-[var(--ink)] font-sans">Error scale factor:</strong> {elaStats.scale_factor}×
            </span>
          )}
          {elaStats?.mean_error !== undefined && (
            <span>
              <strong className="text-[var(--ink)] font-sans">Mean pixel error:</strong> {elaStats.mean_error}
            </span>
          )}
        </div>
      )}

      {/* Educational Guide on Reading the Map */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
        <div className="p-5 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-2 shadow-xs">
          <div className="font-extrabold text-sm text-[var(--ink)] flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[var(--brand)]" />
            <span>How to read AI attention heatmaps</span>
          </div>
          <p className="text-xs text-[var(--mute)] leading-relaxed">
            Warm colors (yellow to dark red) highlight localized pixel groups where convolutional gradients peaked, driving the neural network’s tampering probability.
          </p>
        </div>

        <div className="p-5 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-2 shadow-xs">
          <div className="font-extrabold text-sm text-[var(--ink)] flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[var(--warn)]" />
            <span>How to read compression checks (ELA)</span>
          </div>
          <p className="text-xs text-[var(--mute)] leading-relaxed">
            ELA resaves the image at 95% quality and scales by the 99th percentile. Higher error differentials illuminate in yellow/orange, identifying potential localized spliced fragments.
          </p>
        </div>
      </div>
    </div>
  );
}
