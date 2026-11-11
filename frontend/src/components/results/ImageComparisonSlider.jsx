/**
 * PRAMAANX - Interactive Image Comparison Slider
 * Displays base original evidence specimen on the left and forensic anomaly overlay (Heatmap/ELA) on the right.
 * Synchronizes clipPath clipping with the vertical divider and draggable handle.
 * Provides loading skeletons, graceful error states (no broken browser icons), and full zoom.
 */

import { useState, useRef, useCallback, useEffect } from 'react';
import { ZoomIn, AlertTriangle, Loader2 } from 'lucide-react';

export default function ImageComparisonSlider({
  originalSrc,
  compareSrc,
  originalLabel = 'Original specimen',
  compareLabel = 'AI attention heatmap',
  isEla = false,
  onOpenZoom,
}) {
  const [sliderPosition, setSliderPosition] = useState(50); // percentage 0 to 100
  const [isDragging, setIsDragging] = useState(false);
  const containerRef = useRef(null);

  // Declarative Loading & Error tracking without synchronous effect setState
  const [loadedOriginalSrc, setLoadedOriginalSrc] = useState(null);
  const [failedOriginalSrc, setFailedOriginalSrc] = useState(null);
  const [loadedCompareSrc, setLoadedCompareSrc] = useState(null);
  const [failedCompareSrc, setFailedCompareSrc] = useState(null);

  const isOriginalLoading = Boolean(
    originalSrc && loadedOriginalSrc !== originalSrc && failedOriginalSrc !== originalSrc
  );
  const hasOriginalError = Boolean(originalSrc && failedOriginalSrc === originalSrc);

  const isCompareLoading = Boolean(
    compareSrc && loadedCompareSrc !== compareSrc && failedCompareSrc !== compareSrc
  );
  const hasCompareError = Boolean(compareSrc && failedCompareSrc === compareSrc);

  const handleMove = useCallback((clientX) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const x = clientX - rect.left;
    const percent = Math.min(Math.max((x / rect.width) * 100, 0), 100);
    setSliderPosition(percent);
  }, []);

  const handleTouchMove = useCallback((e) => {
    if (!isDragging) return;
    if (e.touches && e.touches[0]) {
      handleMove(e.touches[0].clientX);
    }
  }, [isDragging, handleMove]);

  const handleMouseMove = useCallback((e) => {
    if (!isDragging) return;
    handleMove(e.clientX);
  }, [isDragging, handleMove]);

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
  }, []);

  useEffect(() => {
    if (isDragging) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', handleMouseUp);
      window.addEventListener('touchmove', handleTouchMove);
      window.addEventListener('touchend', handleMouseUp);
    }
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
      window.removeEventListener('touchmove', handleTouchMove);
      window.removeEventListener('touchend', handleMouseUp);
    };
  }, [isDragging, handleMouseMove, handleMouseUp, handleTouchMove]);

  const isAnyLoading =
    (isOriginalLoading && !hasOriginalError) ||
    (isCompareLoading && !hasCompareError);

  return (
    <div className="space-y-3">
      {/* Container */}
      <div
        ref={containerRef}
        onMouseDown={(e) => {
          setIsDragging(true);
          handleMove(e.clientX);
        }}
        onTouchStart={(e) => {
          if (e.touches && e.touches[0]) {
            setIsDragging(true);
            handleMove(e.touches[0].clientX);
          }
        }}
        className="relative h-[360px] sm:h-[460px] md:h-[520px] rounded-[22px] border border-[var(--line)] bg-black/95 overflow-hidden comparison-slider-container cursor-ew-resize select-none shadow-xs"
        role="region"
        aria-label="Interactive forensic image comparison"
      >
        {/* Loading Indicator Overlay */}
        {isAnyLoading && (
          <div className="absolute inset-0 flex items-center justify-center bg-black/50 pointer-events-none z-10">
            <div className="flex items-center gap-2 text-xs font-medium text-white/90 bg-black/80 px-4 py-2 rounded-full border border-white/20 shadow-md">
              <Loader2 className="w-3.5 h-3.5 text-[var(--brand)] animate-spin" />
              <span>Loading visual layers…</span>
            </div>
          </div>
        )}

        {/* 1. Base Layer: Original Evidence Specimen (Left Side) */}
        {!hasOriginalError && originalSrc ? (
          <img
            src={originalSrc}
            alt={originalLabel}
            onLoad={() => setLoadedOriginalSrc(originalSrc)}
            onError={() => setFailedOriginalSrc(originalSrc)}
            className="absolute inset-0 w-full h-full object-contain pointer-events-none select-none transition-opacity duration-200"
            style={{ opacity: isOriginalLoading ? 0 : 1 }}
          />
        ) : hasOriginalError ? (
          <div
            className="absolute inset-y-0 left-0 flex items-center justify-center p-6 text-center z-10"
            style={{ width: `${sliderPosition}%` }}
          >
            <div className="bg-black/90 border border-[var(--bad)]/40 rounded-2xl p-4 max-w-xs text-xs text-red-200 space-y-1.5 shadow-xl">
              <AlertTriangle className="w-5 h-5 text-[var(--bad)] mx-auto" />
              <p className="font-bold text-white">Original specimen unavailable</p>
              <p className="text-[11px] text-white/70 leading-relaxed">
                The original evidence image could not be loaded from the storage cache.
              </p>
            </div>
          </div>
        ) : null}

        {/* 2. Overlay Layer: Heatmap / ELA Specimen (Right Side, clipped at sliderPosition) */}
        {!hasCompareError && compareSrc ? (
          <img
            src={compareSrc}
            alt={compareLabel}
            onLoad={() => setLoadedCompareSrc(compareSrc)}
            onError={() => setFailedCompareSrc(compareSrc)}
            className={`absolute inset-0 w-full h-full object-contain pointer-events-none select-none transition-opacity duration-200 ${
              isEla ? 'ela-enhanced' : ''
            }`}
            style={{
              clipPath: `inset(0 0 0 ${sliderPosition}%)`,
              opacity: isCompareLoading ? 0 : 1,
            }}
          />
        ) : hasCompareError ? (
          <div
            className="absolute inset-y-0 right-0 flex items-center justify-center p-6 text-center z-10"
            style={{ width: `${100 - sliderPosition}%` }}
          >
            <div className="bg-black/90 border border-[var(--warn)]/40 rounded-2xl p-4 max-w-xs text-xs text-amber-200 space-y-1.5 shadow-xl">
              <AlertTriangle className="w-5 h-5 text-[var(--warn)] mx-auto" />
              <p className="font-bold text-white">
                {isEla ? 'Compression map unavailable' : 'Heatmap could not be loaded'}
              </p>
              <p className="text-[11px] text-white/70 leading-relaxed">
                The forensic anomaly layer could not be rendered for this specimen.
              </p>
            </div>
          </div>
        ) : null}

        {/* 3. Vertical Divider Line */}
        <div
          className="absolute top-0 bottom-0 w-0.5 bg-white shadow-[0_0_12px_rgba(0,0,0,0.8)] pointer-events-none z-20"
          style={{ left: `${sliderPosition}%` }}
        />

        {/* 4. Draggable Center Handle */}
        <div
          className="absolute top-1/2 -translate-y-1/2 -translate-x-1/2 w-9 h-9 rounded-full bg-white text-zinc-900 shadow-[0_4px_16px_rgba(0,0,0,0.5)] flex items-center justify-center border-2 border-white/80 text-xs font-bold pointer-events-auto cursor-grab active:cursor-grabbing hover:scale-110 active:scale-95 transition-transform z-30 select-none"
          style={{ left: `${sliderPosition}%` }}
          title="Drag left and right to inspect changes"
          aria-label="Comparison slider handle"
        >
          ↔
        </div>

        {/* 5. Floating Labels */}
        <div className="absolute top-3.5 left-3.5 bg-black/80 backdrop-blur-xs text-white text-xs font-bold px-3.5 py-1.5 rounded-full border border-white/20 pointer-events-none shadow-md z-20 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-[var(--ok)]" />
          <span>{originalLabel}</span>
        </div>

        <div className="absolute top-3.5 right-3.5 bg-black/80 backdrop-blur-xs text-white text-xs font-bold px-3.5 py-1.5 rounded-full border border-white/20 pointer-events-none shadow-md z-20 flex items-center gap-2">
          <span
            className={`w-2 h-2 rounded-full ${
              isEla ? 'bg-[var(--warn)]' : 'bg-[var(--brand)]'
            }`}
          />
          <span>{compareLabel}</span>
        </div>

        {/* 6. Full Zoom Action Button */}
        {onOpenZoom && (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onOpenZoom({
                title: `${originalLabel} vs ${compareLabel}`,
                src: compareSrc || originalSrc,
                caption: 'Interactive comparison specimen. Use slider to inspect boundary anomalies.',
              });
            }}
            className="absolute bottom-3.5 right-3.5 px-3.5 py-1.5 rounded-full bg-black/80 hover:bg-black text-white text-xs font-bold border border-white/20 flex items-center gap-1.5 shadow-lg transition-colors cursor-pointer z-20"
          >
            <ZoomIn className="w-3.5 h-3.5" />
            <span>Full zoom</span>
          </button>
        )}
      </div>

      {/* Caption & Position Readout */}
      <div className="flex items-center justify-between text-xs text-[var(--mute)] px-1">
        <span>Drag divider left and right to inspect localized differences</span>
        <span className="font-mono font-medium">Split: {Math.round(sliderPosition)}%</span>
      </div>
    </div>
  );
}
