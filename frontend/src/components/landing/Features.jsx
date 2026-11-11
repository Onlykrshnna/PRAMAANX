import { useState, useEffect } from 'react';
import {
  CheckCircle2,
  AlertTriangle,
  Fingerprint,
  SlidersHorizontal,
  Layers,
  Sparkles,
  FileCheck,
  ShieldCheck,
  Download,
} from 'lucide-react';
import { useReveal } from '../../hooks/useReveal';
import { usePrefersReducedMotion } from '../../hooks/usePrefersReducedMotion';
import Card from '../common/Card';
import SectionHead from '../common/SectionHead';
import Pill from '../common/Pill';

export default function Features() {
  const [ref, isRevealed] = useReveal({ threshold: 0.1 });
  const prefersReduced = usePrefersReducedMotion();

  // (a) Staggered Lighting up of the Five Checks (0.5s stagger)
  const [activeCheckIndex, setActiveCheckIndex] = useState(0);
  const effectiveActiveCheckIndex = prefersReduced ? 5 : activeCheckIndex;

  useEffect(() => {
    if (prefersReduced || !isRevealed) return;

    const interval = setInterval(() => {
      setActiveCheckIndex((prev) => {
        if (prev < 5) return prev + 1;
        return prev;
      });
    }, 500);

    return () => clearInterval(interval);
  }, [isRevealed, prefersReduced]);

  // (b) Real Simple / Technical View Mode Toggle
  const [viewMode, setViewMode] = useState('simple'); // 'simple' | 'technical'

  // (c) Draggable Heatmap Reveal Slider
  const [sliderPos, setSliderPos] = useState(50); // percentage 0 - 100

  // (d) File Hash Real-Time Typing Animation (22ms per char)
  const fullHash = '752fd0993d356a7d9c48b201a7428f52019b882e';
  const [typedHash, setTypedHash] = useState('');
  const effectiveTypedHash = prefersReduced ? fullHash : typedHash;

  useEffect(() => {
    if (prefersReduced || !isRevealed) return;

    let index = 0;
    const timer = setInterval(() => {
      index++;
      setTypedHash(fullHash.slice(0, index));
      if (index >= fullHash.length) {
        clearInterval(timer);
      }
    }, 22);

    return () => clearInterval(timer);
  }, [isRevealed, prefersReduced]);

  const checksData = [
    { name: 'File header', status: 'Passed', isOk: true },
    { name: 'Byte patterns', status: 'Passed', isOk: true },
    { name: 'Metadata', status: 'Passed', isOk: true },
    { name: 'Compression', status: 'Flagged', isOk: false },
    { name: 'AI screening', status: 'Flagged', isOk: false },
  ];

  return (
    <section
      id="features"
      ref={ref}
      className={`landing-section space-y-12 reveal-section ${
        isRevealed ? 'revealed' : ''
      }`}
    >
      {/* Section Head: NO eyebrows, NO gradient text */}
      <SectionHead
        title="Everything you need to trust a result"
        subtitle="Five automated checks, one clear verdict, and the evidence behind it."
      />

      {/* 6-Column Bento Grid matching reference */}
      <div className="grid grid-cols-1 md:grid-cols-6 gap-6 sm:gap-7">
        {/* Card A: Five checks, one verdict (span 3) */}
        <Card className="md:col-span-3 flex flex-col justify-between" lift>
          <div className="space-y-3">
            <div className="w-10 h-10 rounded-2xl bg-[var(--soft)] border border-[var(--line)] flex items-center justify-center text-[var(--brand)]">
              <Layers className="w-5 h-5" />
            </div>
            <h3 className="text-xl font-bold tracking-tight text-[var(--ink)]">
              Five checks, one verdict
            </h3>
            <p className="text-sm text-[var(--mute)] leading-relaxed">
              Each file runs through the same inspection pipeline.
            </p>
          </div>

          {/* Staggered Light-Up Checklist */}
          <div className="mt-6 rounded-[16px] border border-[var(--line)] bg-[var(--soft)]/40 divide-y divide-[var(--line)] font-mono text-xs overflow-hidden">
            {checksData.map((check, idx) => {
              const isLit = idx < effectiveActiveCheckIndex;
              return (
                <div
                  key={check.name}
                  className={`p-3 flex items-center justify-between transition-all duration-300 ${
                    isLit ? 'opacity-100 bg-[var(--card)]' : 'opacity-35 bg-transparent'
                  }`}
                >
                  <span className="text-[var(--ink)] font-medium font-sans text-sm">
                    {check.name}
                  </span>
                  <span
                    className={`inline-flex items-center gap-1.5 font-bold italic ${
                      check.isOk ? 'text-[var(--ok)]' : 'text-[var(--warn)]'
                    }`}
                  >
                    {check.isOk ? (
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    ) : (
                      <AlertTriangle className="w-3.5 h-3.5" />
                    )}
                    {check.status}
                  </span>
                </div>
              );
            })}
          </div>
        </Card>

        {/* Card B: Simple or technical, your call (span 3) */}
        <Card className="md:col-span-3 flex flex-col justify-between" lift>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="w-10 h-10 rounded-2xl bg-[var(--soft)] border border-[var(--line)] flex items-center justify-center text-[var(--brand)]">
                <SlidersHorizontal className="w-5 h-5" />
              </div>

              {/* Segmented Toggle Control */}
              <div
                role="group"
                aria-label="View toggle"
                className="inline-flex items-center p-1 rounded-full border border-[var(--line)] bg-[var(--soft)]"
              >
                <button
                  type="button"
                  onClick={() => setViewMode('simple')}
                  className={`px-3 py-1 rounded-full text-xs font-mono font-medium transition-all cursor-pointer ${
                    viewMode === 'simple'
                      ? 'bg-[var(--card)] text-[var(--ink)] shadow-xs font-bold'
                      : 'text-[var(--mute)] hover:text-[var(--ink)]'
                  }`}
                >
                  Simple
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode('technical')}
                  className={`px-3 py-1 rounded-full text-xs font-mono font-medium transition-all cursor-pointer ${
                    viewMode === 'technical'
                      ? 'bg-[var(--card)] text-[var(--ink)] shadow-xs font-bold'
                      : 'text-[var(--mute)] hover:text-[var(--ink)]'
                  }`}
                >
                  Technical
                </button>
              </div>
            </div>

            <h3 className="text-xl font-bold tracking-tight text-[var(--ink)]">
              Simple or technical, your call
            </h3>
            <p className="text-sm text-[var(--mute)] leading-relaxed">
              Beginners get words. Experts get the raw data.
            </p>
          </div>

          {/* Real Swapping Content */}
          <div className="mt-6 min-h-[140px] flex items-center">
            {viewMode === 'simple' ? (
              <div className="w-full p-4 rounded-[16px] border border-[var(--status-medium-border)] bg-[var(--status-medium-bg)]/40 text-sm text-[var(--ink)] leading-relaxed">
                <strong className="text-[var(--warn)] font-bold">
                  Possible edits detected.
                </strong>{' '}
                The sky and the ground were saved differently, which can happen when something is pasted in.
              </div>
            ) : (
              <div className="w-full p-4 rounded-[16px] border border-[var(--line)] bg-[var(--soft)]/70 font-mono text-xs space-y-1.5 text-[var(--mute)] leading-relaxed">
                <div className="text-[var(--ink)] font-semibold">
                  SHA-256 752fd0993d356a7d…
                </div>
                <div>Shannon entropy 7.964 / 8.000</div>
                <div>ELA residual p99 = 41.2</div>
                <div className="text-[var(--brand)] font-semibold">
                  EfficientNet-B0 · experimental
                </div>
              </div>
            )}
          </div>
        </Card>

        {/* Card C: Proof you can see (span 3 or 4) */}
        <Card className="md:col-span-3 lg:col-span-4 flex flex-col justify-between" lift>
          <div className="space-y-3">
            <div className="w-10 h-10 rounded-2xl bg-[var(--soft)] border border-[var(--line)] flex items-center justify-center text-[var(--brand)]">
              <Sparkles className="w-5 h-5" />
            </div>
            <h3 className="text-xl font-bold tracking-tight text-[var(--ink)]">
              Proof you can see
            </h3>
            <p className="text-sm text-[var(--mute)] leading-relaxed">
              Drag to reveal where the AI looked.
            </p>
          </div>

          {/* Interactive Drag Reveal Slider Showcase */}
          <div className="mt-6 space-y-3">
            <div className="relative w-full h-48 rounded-[16px] overflow-hidden border border-[var(--line)] select-none bg-[#0a071d]">
              {/* Heatmap Layer Behind */}
              <div
                className="absolute inset-0 flex items-center justify-end pr-6 font-mono text-xs font-bold text-white pointer-events-none"
                style={{
                  background:
                    'radial-gradient(circle at 70% 50%, rgba(239, 68, 68, 0.9) 0%, rgba(245, 158, 11, 0.8) 35%, rgba(91, 61, 245, 0.45) 70%, #0c0922 100%)',
                }}
              >
                <span className="px-3 py-1 rounded-full bg-black/60 border border-white/20">
                  Heatmap layer
                </span>
              </div>

              {/* Original Layer Clipped to Slider Position */}
              <div
                className="absolute inset-y-0 left-0 overflow-hidden bg-slate-900 border-r-2 border-white shadow-2xl flex items-center justify-start pl-6"
                style={{ width: `${sliderPos}%` }}
              >
                <div className="w-[600px] h-full flex items-center font-mono text-xs text-slate-300 bg-gradient-to-tr from-slate-950 to-slate-800">
                  <span className="px-3 py-1 rounded-full bg-black/60 border border-white/20">
                    Original specimen
                  </span>
                </div>
              </div>
            </div>

            {/* Slider Range Control */}
            <div className="flex items-center gap-3 pt-1">
              <span className="text-xs font-mono text-[var(--mute)]">Original</span>
              <input
                type="range"
                min="0"
                max="100"
                value={sliderPos}
                onChange={(e) => setSliderPos(Number(e.target.value))}
                className="w-full accent-[var(--brand)] cursor-pointer"
                aria-label="Drag to reveal where the AI looked."
              />
              <span className="text-xs font-mono text-[var(--mute)]">Heatmap</span>
            </div>
          </div>
        </Card>

        {/* Card D: A fingerprint for every file (span 3 or 2) */}
        <Card className="md:col-span-3 lg:col-span-2 flex flex-col justify-between" lift>
          <div className="space-y-3">
            <div className="w-10 h-10 rounded-2xl bg-[var(--soft)] border border-[var(--line)] flex items-center justify-center text-[var(--brand)]">
              <Fingerprint className="w-5 h-5" />
            </div>
            <h3 className="text-xl font-bold tracking-tight text-[var(--ink)]">
              A fingerprint for every file
            </h3>
            <p className="text-sm text-[var(--mute)] leading-relaxed">
              The hash is calculated before any analysis, so you can prove the file was never changed.
            </p>
          </div>

          <div className="mt-6 space-y-4">
            {/* Real-time typing hash box */}
            <div className="p-3.5 rounded-[16px] border border-[var(--line)] bg-[var(--soft)]/70 font-mono text-xs break-all text-[var(--ink)] min-h-[58px] flex items-center">
              <span>{effectiveTypedHash}</span>
              <span className="inline-block w-2 h-4 bg-[var(--brand)] ml-1 animate-pulse" />
            </div>

            {/* Tags */}
            <div className="flex flex-wrap gap-2">
              <Pill icon={ShieldCheck} variant="default" size="sm">
                No cloud upload
              </Pill>
              <Pill icon={FileCheck} variant="default" size="sm">
                Chain of custody
              </Pill>
              <Pill icon={Download} variant="default" size="sm">
                Exportable PDF report
              </Pill>
            </div>
          </div>
        </Card>
      </div>
    </section>
  );
}
