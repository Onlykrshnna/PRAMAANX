/**
 * PRAMAANX - Interactive Image Forensic Overlay
 * Visual centerpiece: layer switcher (Original / AI Heatmap / Compression ELA),
 * live opacity blend slider, hover region annotation, full zoom modal,
 * and robust loading/error states without broken browser image icons.
 */

import { useState } from 'react';
import { ZoomIn, Info, FileText, Sparkles, Sliders, AlertTriangle, Loader2 } from 'lucide-react';

export default function InteractiveImageOverlay({
  originalUrl,
  gradcamUrl,
  elaUrl,
  fileName,
  fileType,
  detectedMime,
  onOpenZoom,
}) {
  const [activeLayer, setActiveLayer] = useState(gradcamUrl ? 'heatmap' : 'original');
  const [overlayOpacity, setOverlayOpacity] = useState(65); // 0 to 100%
  const [isHoveringHeatmap, setIsHoveringHeatmap] = useState(false);
  const [elaEnhanced, _setElaEnhanced] = useState(true);

  // Declarative Loading & Error tracking
  const [loadedOriginal, setLoadedOriginal] = useState(null);
  const [failedOriginal, setFailedOriginal] = useState(null);
  const [loadedHeatmap, setLoadedHeatmap] = useState(null);
  const [failedHeatmap, setFailedHeatmap] = useState(null);
  const [loadedEla, setLoadedEla] = useState(null);
  const [failedEla, setFailedEla] = useState(null);

  const originalLoading = Boolean(
    originalUrl && loadedOriginal !== originalUrl && failedOriginal !== originalUrl
  );
  const originalError = Boolean(originalUrl && failedOriginal === originalUrl);

  const heatmapLoading = Boolean(
    gradcamUrl && loadedHeatmap !== gradcamUrl && failedHeatmap !== gradcamUrl
  );
  const heatmapError = Boolean(gradcamUrl && failedHeatmap === gradcamUrl);

  const elaLoading = Boolean(
    elaUrl && loadedEla !== elaUrl && failedEla !== elaUrl
  );
  const elaError = Boolean(elaUrl && failedEla === elaUrl);

  const isImage = Boolean(
    fileType === 'image' || (detectedMime && detectedMime.startsWith('image/'))
  );

  // If not an image (e.g. PDF, Office, ZIP), show a clean visual document inspection canvas
  if (!isImage || (!originalUrl && !gradcamUrl && !elaUrl)) {
    return (
      <div className="rounded-[22px] border border-[var(--line)] bg-[var(--card)] p-8 flex flex-col items-center justify-center text-center space-y-4 aspect-4/3 min-h-[320px] shadow-xs">
        <div className="w-16 h-16 rounded-2xl bg-[var(--soft)] border border-[var(--line)] flex items-center justify-center text-[var(--brand)] shadow-xs">
          <FileText className="w-8 h-8" />
        </div>
        <div className="space-y-1 max-w-sm">
          <h4 className="font-extrabold text-base text-[var(--ink)] tracking-tight truncate">
            {fileName || 'Document Specimen'}
          </h4>
          <p className="text-xs text-[var(--mute)] font-mono">
            {detectedMime || 'Structured Document Container'}
          </p>
        </div>
        <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full text-xs font-semibold text-[var(--brand)] bg-[var(--soft)] border border-[var(--line)]">
          <Sparkles className="w-3.5 h-3.5" />
          <span>AST Object Stream & Macro Inspection Active</span>
        </div>
      </div>
    );
  }

  const currentDisplayUrl =
    activeLayer === 'heatmap' && gradcamUrl && !heatmapError
      ? gradcamUrl
      : activeLayer === 'ela' && elaUrl && !elaError
      ? elaUrl
      : (!originalError && originalUrl) || gradcamUrl || elaUrl;

  const isCurrentLayerLoading =
    (activeLayer === 'original' && originalLoading && !originalError) ||
    (activeLayer === 'heatmap' && heatmapLoading && !heatmapError) ||
    (activeLayer === 'ela' && elaLoading && !elaError);

  const currentLayerHasError =
    (activeLayer === 'original' && originalError) ||
    (activeLayer === 'heatmap' && heatmapError && (!originalUrl || originalError)) ||
    (activeLayer === 'ela' && elaError);

  return (
    <div className="rounded-[22px] border border-[var(--line)] bg-[var(--card)] overflow-hidden shadow-xs flex flex-col">
      {/* Top Controls Bar: Layer Switcher & Zoom */}
      <div className="p-3 sm:p-4 border-b border-[var(--line)] bg-[var(--card)] flex flex-wrap items-center justify-between gap-2.5">
        {/* Layer Switcher - Segmented Rounded Pill */}
        <div
          role="tablist"
          aria-label="Visual inspection layer"
          className="inline-flex items-center p-1 rounded-full border border-[var(--line)] bg-[var(--soft)]"
        >
          {originalUrl && (
            <button
              type="button"
              role="tab"
              aria-selected={activeLayer === 'original'}
              onClick={() => setActiveLayer('original')}
              className={`px-3.5 py-1 rounded-full text-xs font-bold transition-all cursor-pointer ${
                activeLayer === 'original'
                  ? 'bg-[var(--card)] text-[var(--ink)] shadow-xs border border-[var(--line)]'
                  : 'text-[var(--mute)] hover:text-[var(--ink)]'
              }`}
            >
              Original
            </button>
          )}

          {gradcamUrl && (
            <button
              type="button"
              role="tab"
              aria-selected={activeLayer === 'heatmap'}
              onClick={() => setActiveLayer('heatmap')}
              className={`flex items-center gap-1.5 px-3.5 py-1 rounded-full text-xs font-bold transition-all cursor-pointer ${
                activeLayer === 'heatmap'
                  ? 'bg-[var(--card)] text-[var(--brand)] shadow-xs border border-[var(--line)]'
                  : 'text-[var(--mute)] hover:text-[var(--ink)]'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-[var(--brand)]" />
              <span>AI Heatmap</span>
            </button>
          )}

          {elaUrl && (
            <button
              type="button"
              role="tab"
              aria-selected={activeLayer === 'ela'}
              onClick={() => setActiveLayer('ela')}
              className={`flex items-center gap-1.5 px-3.5 py-1 rounded-full text-xs font-bold transition-all cursor-pointer ${
                activeLayer === 'ela'
                  ? 'bg-[var(--card)] text-[var(--warn)] shadow-xs border border-[var(--line)]'
                  : 'text-[var(--mute)] hover:text-[var(--ink)]'
              }`}
            >
              <span className="w-2 h-2 rounded-full bg-[var(--warn)]" />
              <span>ELA</span>
            </button>
          )}
        </div>

        {/* Zoom Trigger */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() =>
              onOpenZoom &&
              onOpenZoom({
                title:
                  activeLayer === 'heatmap'
                    ? 'AI Attention Heatmap (Grad-CAM)'
                    : activeLayer === 'ela'
                    ? 'Compression Inconsistency (ELA)'
                    : 'Original Evidence Specimen',
                src: currentDisplayUrl,
                caption:
                  activeLayer === 'heatmap'
                    ? 'Warm colored areas highlight regions that drove the AI model suspicious classification.'
                    : activeLayer === 'ela'
                    ? 'Bright pixel clusters highlight compression inconsistencies from resaving or splicing.'
                    : 'Original image as uploaded in this session.',
              })
            }
            className="flex items-center gap-1.5 px-3.5 py-1 rounded-full border border-[var(--line)] bg-[var(--card)] text-xs font-bold text-[var(--ink)] hover:bg-[var(--soft)] hover:border-[var(--brand)] transition-all cursor-pointer shadow-xs"
            title="Expand to full screen"
          >
            <ZoomIn className="w-3.5 h-3.5 text-[var(--mute)]" />
            <span>Zoom</span>
          </button>
        </div>
      </div>

      {/* Main Visual Display Viewport with interactive overlay */}
      <div
        className="relative bg-black/95 aspect-4/3 sm:aspect-16/10 flex items-center justify-center overflow-hidden cursor-zoom-in"
        onClick={() =>
          onOpenZoom &&
          onOpenZoom({
            title:
              activeLayer === 'heatmap'
                ? 'AI Attention Heatmap (Grad-CAM)'
                : activeLayer === 'ela'
                ? 'Compression Inconsistency (ELA)'
                : 'Original Evidence Specimen',
            src: currentDisplayUrl,
            caption:
              activeLayer === 'heatmap'
                ? 'Warm colored areas highlight regions that drove the AI model suspicious classification.'
                : activeLayer === 'ela'
                ? 'Bright pixel clusters highlight compression inconsistencies from resaving or splicing.'
                : 'Original image as uploaded in this session.',
          })
        }
        onMouseEnter={() => setIsHoveringHeatmap(true)}
        onMouseLeave={() => setIsHoveringHeatmap(false)}
      >
        {/* Loading Spinner */}
        {isCurrentLayerLoading && (
          <div className="absolute inset-0 flex items-center justify-center bg-black/40 pointer-events-none z-10">
            <div className="flex items-center gap-2 text-xs font-medium text-white/90 bg-black/80 px-3.5 py-1.5 rounded-full border border-white/20 shadow-md">
              <Loader2 className="w-3.5 h-3.5 text-[var(--brand)] animate-spin" />
              <span>Loading visual specimen…</span>
            </div>
          </div>
        )}

        {/* Error Fallback */}
        {currentLayerHasError && (
          <div className="p-6 text-center space-y-2 z-10 max-w-xs bg-black/85 rounded-2xl border border-[var(--line)]">
            <AlertTriangle className="w-6 h-6 text-[var(--warn)] mx-auto" />
            <p className="text-xs font-bold text-white">
              {activeLayer === 'original'
                ? 'Original specimen unavailable'
                : activeLayer === 'heatmap'
                ? 'Heatmap could not be loaded'
                : 'Compression map unavailable'}
            </p>
            <p className="text-[11px] text-white/70">
              The requested visual layer is currently not available from the evidence storage vault.
            </p>
          </div>
        )}

        {/* Base Layer: Original Image */}
        {originalUrl && !originalError && (
          <img
            src={originalUrl}
            alt="Original forensic specimen"
            onLoad={() => setLoadedOriginal(originalUrl)}
            onError={() => setFailedOriginal(originalUrl)}
            className="absolute inset-0 w-full h-full object-contain pointer-events-none select-none transition-opacity duration-200"
            style={{ opacity: originalLoading ? 0 : 1 }}
          />
        )}

        {/* Heatmap Overlay with Opacity blending */}
        {activeLayer === 'heatmap' && gradcamUrl && !heatmapError && (
          <img
            src={gradcamUrl}
            alt="AI Attention Heatmap overlay"
            onLoad={() => setLoadedHeatmap(gradcamUrl)}
            onError={() => setFailedHeatmap(gradcamUrl)}
            className="absolute inset-0 w-full h-full object-contain mix-blend-multiply pointer-events-none select-none transition-opacity duration-150"
            style={{
              opacity: heatmapLoading ? 0 : originalUrl && !originalError ? overlayOpacity / 100 : 1,
            }}
          />
        )}

        {/* ELA Layer */}
        {activeLayer === 'ela' && elaUrl && !elaError && (
          <img
            src={elaUrl}
            alt="Error Level Analysis"
            onLoad={() => setLoadedEla(elaUrl)}
            onError={() => setFailedEla(elaUrl)}
            className={`absolute inset-0 w-full h-full object-contain pointer-events-none select-none transition-opacity duration-200 ${
              elaEnhanced ? 'ela-enhanced' : ''
            }`}
            style={{ opacity: elaLoading ? 0 : 1 }}
          />
        )}

        {/* Hover Flag Annotation */}
        {activeLayer === 'heatmap' && isHoveringHeatmap && !heatmapError && (
          <div className="absolute bottom-3 left-3 bg-black/80 backdrop-blur-xs text-white text-xs px-3 py-1.5 rounded-full border border-white/20 shadow-md flex items-center gap-1.5 pointer-events-none transition-opacity z-20">
            <Info className="w-3.5 h-3.5 text-[var(--brand)]" />
            <span>Region flagged by AI attention gradients</span>
          </div>
        )}
      </div>

      {/* Bottom Slider & Caption Bar */}
      {activeLayer === 'heatmap' && originalUrl && !originalError && gradcamUrl && !heatmapError && (
        <div className="p-3 sm:px-4 border-t border-[var(--line)] bg-[var(--soft)]/50 flex items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2 text-[var(--mute)] shrink-0">
            <Sliders className="w-3.5 h-3.5 text-[var(--brand)]" />
            <span className="font-semibold text-[var(--ink)]">Heatmap blend:</span>
          </div>
          <input
            type="range"
            min="0"
            max="100"
            value={overlayOpacity}
            onChange={(e) => setOverlayOpacity(Number(e.target.value))}
            className="w-full max-w-xs accent-[var(--brand)] cursor-pointer"
            title={`Overlay Opacity: ${overlayOpacity}%`}
            aria-label="Heatmap opacity slider"
          />
          <span className="font-mono font-bold text-[var(--ink)] text-xs w-10 text-right shrink-0">
            {overlayOpacity}%
          </span>
        </div>
      )}

      {/* Helpful 1-line caption */}
      <div className="p-3 px-4 bg-[var(--soft)]/30 text-xs text-[var(--mute)] flex items-center justify-between border-t border-[var(--line)]">
        <span>
          {activeLayer === 'heatmap'
            ? 'Warm colors show where neural network attention focused.'
            : activeLayer === 'ela'
            ? 'High brightness indicates compression variance from potential splicing.'
            : 'Original uncompressed evidence as received.'}
        </span>
        <span className="text-[11px] text-[var(--mute)] font-medium hidden sm:inline">
          Click image to zoom
        </span>
      </div>
    </div>
  );
}
