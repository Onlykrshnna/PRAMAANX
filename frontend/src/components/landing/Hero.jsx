import { useState, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, FileSearch, ShieldAlert } from 'lucide-react';
import { useReveal } from '../../hooks/useReveal';
import { usePrefersReducedMotion } from '../../hooks/usePrefersReducedMotion';
import Gauge from '../common/Gauge';
import SignalChip from '../common/SignalChip';
import ViewTabs from '../common/ViewTabs';
import { ROUTES } from '../../utils/constants';

export default function Hero() {
  const [ref, isRevealed] = useReveal({ threshold: 0.1 });
  const prefersReduced = usePrefersReducedMotion();
  const navigate = useNavigate();

  // Active view tab inside the sample window: 'original' | 'heatmap' | 'compression'
  const [activeTab, setActiveTab] = useState('heatmap');

  // Mouse tilt state
  const windowRef = useRef(null);
  const [tilt, setTilt] = useState({ x: 0, y: 0 });

  const handleMouseMove = useCallback((e) => {
    if (prefersReduced || !windowRef.current) return;
    const rect = windowRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;

    // Max 6deg on Y axis, max 5deg on X axis
    const rotateY = ((x - centerX) / centerX) * 6;
    const rotateX = -((y - centerY) / centerY) * 5;

    setTilt({ x: rotateX, y: rotateY });
  }, [prefersReduced]);

  const handleMouseLeave = useCallback(() => {
    setTilt({ x: 0, y: 0 });
  }, []);

  return (
    <section
      id="top"
      ref={ref}
      className={`relative pt-16 sm:pt-24 pb-20 overflow-visible text-center reveal-section ${
        isRevealed ? 'revealed' : ''
      }`}
    >
      {/* Main Container */}
      <div className="max-w-[1160px] mx-auto px-6 space-y-8 relative z-10">
        {/* Centered Headline: Solid Off-White, Editorial Typography */}
        <div className="mx-auto max-w-[1000px] py-1 sm:py-3">
          <h1 className="hero-headline-upgrade mx-auto text-center text-[var(--ink)]">
            <span className="block hero-line-1">
              Every file has
            </span>
            <span className="block hero-line-2">
              its own history.
            </span>
            <span className="block hero-line-3">
              Discover what changed.
            </span>
          </h1>
        </div>

        {/* Subtext */}
        <p
          className="mx-auto text-center font-medium"
          style={{
            fontFamily: 'Manrope, sans-serif',
            fontSize: 'clamp(16px, 1.6vw, 19px)',
            fontWeight: 500,
            lineHeight: 1.6,
            color: 'var(--mute)',
            maxWidth: '52ch',
            textWrap: 'balance',
            hyphens: 'manual',
            WebkitHyphens: 'manual',
          }}
        >
          Private, explainable image forensics. Upload a file and get a plain&#8209;English verdict with visual proof, all on your own device.
        </p>

        {/* Two CTAs */}
        <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
          <button
            type="button"
            onClick={() => navigate(ROUTES.ANALYZE)}
            className="inline-flex items-center gap-2.5 px-6 py-3.5 rounded-full text-sm font-bold bg-[var(--brand)] text-white hover:opacity-95 shadow-md shadow-[var(--brand)]/25 lift-button cursor-pointer"
          >
            <FileSearch className="w-4 h-4" />
            <span>Analyze an image</span>
          </button>
          <a
            href="#features"
            className="inline-flex items-center gap-2 px-6 py-3.5 rounded-full text-sm font-bold bg-[var(--card)] text-[var(--ink)] border border-[var(--line)] hover:border-[var(--brand)] hover:text-[var(--brand)] shadow-xs lift-button cursor-pointer"
          >
            <span>See a sample report</span>
            <ArrowRight className="w-4 h-4" />
          </a>
        </div>

        {/* Interactive Tilting Product Window Showcase */}
        <div className="relative pt-10 pb-6 max-w-[920px] mx-auto">
          {/* Floating Role Chips around the window */}
          <div className="hidden sm:inline-flex absolute -top-1 left-2 sm:-left-6 z-20 px-3.5 py-1.5 rounded-full text-xs font-medium border border-[var(--line)] bg-[var(--card)] text-[var(--ink)] shadow-md animate-float-0">
            Journalist
          </div>
          <div className="hidden sm:inline-flex absolute top-1/4 -right-4 sm:-right-8 z-20 px-3.5 py-1.5 rounded-full text-xs font-medium border border-[var(--line)] bg-[var(--card)] text-[var(--ink)] shadow-md animate-float-1">
            Investigator
          </div>
          <div className="hidden sm:inline-flex absolute bottom-8 -left-4 sm:-left-8 z-20 px-3.5 py-1.5 rounded-full text-xs font-medium border border-[var(--line)] bg-[var(--card)] text-[var(--ink)] shadow-md animate-float-2">
            Student
          </div>
          <div className="hidden sm:inline-flex absolute -bottom-3 right-4 sm:-right-4 z-20 px-3.5 py-1.5 rounded-full text-xs font-medium border border-[var(--line)] bg-[var(--card)] text-[var(--ink)] shadow-md animate-float-3">
            Security analyst
          </div>

          {/* Product Window Frame */}
          <div
            ref={windowRef}
            onMouseMove={handleMouseMove}
            onMouseLeave={handleMouseLeave}
            style={{
              transform: prefersReduced
                ? 'none'
                : `perspective(1000px) rotateX(${tilt.x}deg) rotateY(${tilt.y}deg)`,
            }}
            className="rounded-[22px] border border-[var(--line)] bg-[var(--card)] shadow-2xl shadow-[var(--glow)]/40 overflow-hidden transition-transform duration-200 ease-out text-left"
          >
            {/* Window Top Bar */}
            <div className="px-5 py-3.5 border-b border-[var(--line)] bg-[var(--soft)]/70 flex items-center justify-between text-xs font-medium text-[var(--mute)]">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-[var(--bad)] opacity-80" />
                <span className="w-2.5 h-2.5 rounded-full bg-[var(--warn)] opacity-80" />
                <span className="w-2.5 h-2.5 rounded-full bg-[var(--ok)] opacity-80" />
                <span className="ml-2 font-mono text-xs text-[var(--ink)] font-semibold">
                  sample_photo.jpg · Forensic report
                </span>
              </div>
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium bg-[var(--card)] border border-[var(--line)] text-[var(--mute)]">
                Sample preview
              </span>
            </div>

            {/* Window Content: 2 Columns */}
            <div className="grid grid-cols-1 md:grid-cols-12 min-h-[380px]">
              {/* Left Panel: Specimen & ViewTabs */}
              <div className="md:col-span-7 bg-[#0b081e] p-5 sm:p-6 flex flex-col justify-between relative overflow-hidden text-white">
                {/* ViewTabs Control */}
                <div className="relative z-10 flex justify-between items-center">
                  <ViewTabs
                    activeTab={activeTab}
                    onChange={setActiveTab}
                    className="bg-black/60 border-white/10"
                  />
                  <span className="text-[11px] font-mono text-white/60">
                    2048 × 1536 px
                  </span>
                </div>

                {/* Simulated Specimen / Heatmap View */}
                <div className="my-auto py-8 relative flex items-center justify-center">
                  {/* Scan line animation */}
                  <div className="animate-scan-line absolute left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-[var(--brand)] to-transparent shadow-[0_0_12px_var(--brand)] pointer-events-none z-10" />

                  {activeTab === 'original' ? (
                    <div className="w-full h-48 rounded-xl bg-gradient-to-tr from-slate-900 to-indigo-950 border border-white/10 flex items-center justify-center font-mono text-xs text-slate-300">
                      Original specimen (unprocessed pixels)
                    </div>
                  ) : activeTab === 'heatmap' ? (
                    <div
                      className="w-full h-48 rounded-xl border border-white/20 flex items-center justify-center font-mono text-xs font-bold text-white relative overflow-hidden"
                      style={{
                        background:
                          'radial-gradient(circle at 65% 45%, rgba(239, 68, 68, 0.9) 0%, rgba(245, 158, 11, 0.75) 30%, rgba(91, 61, 245, 0.5) 60%, #0d0a27 100%)',
                      }}
                    >
                      <div className="px-3 py-1.5 rounded-md bg-black/60 backdrop-blur-xs border border-white/20">
                        Attention gradient anomaly detected
                      </div>
                    </div>
                  ) : (
                    <div className="w-full h-48 rounded-xl bg-[#120f2e] border border-white/15 flex items-center justify-center font-mono text-xs text-purple-300">
                      Error Level Analysis (quantization variance p99 = 41.2)
                    </div>
                  )}
                </div>

                {/* Bottom Bar Info */}
                <div className="relative z-10 flex items-center justify-between text-[11px] font-mono text-white/70 pt-2 border-t border-white/10">
                  <span>SHA-256: 752fd099...3d35</span>
                  <span>JPEG Q=92</span>
                </div>
              </div>

              {/* Right Panel: Verdict & Signal Chips */}
              <div className="md:col-span-5 p-6 sm:p-7 flex flex-col justify-between space-y-6 bg-[var(--card)]">
                {/* Semicircle Gauge */}
                <div className="flex flex-col items-center pt-2">
                  <Gauge score={58} size={190} riskLabel="Review Advised" />
                </div>

                {/* Verdict Headline & Plain-English Copy */}
                <div className="space-y-2 p-4 rounded-[16px] bg-[var(--soft)]/50 border border-[var(--line)]">
                  <div className="flex items-center gap-2 text-[var(--warn)] font-bold text-sm">
                    <ShieldAlert className="w-4 h-4 flex-shrink-0" />
                    <h3 className="font-extrabold tracking-tight text-[var(--ink)] text-sm sm:text-base">
                      Possible edits detected
                    </h3>
                  </div>
                  <p className="text-xs text-[var(--mute)] leading-relaxed pl-6">
                    One area shows different compression than the rest. Open the heatmap to see where.
                  </p>
                </div>

                {/* Five Signal Chips */}
                <div className="space-y-2">
                  <div className="text-[11px] font-mono font-medium text-[var(--mute)] uppercase tracking-wider">
                    Pipeline validation checks
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    <SignalChip label="Header" status="Passed" />
                    <SignalChip label="Byte data" status="Passed" />
                    <SignalChip label="Metadata" status="Passed" />
                    <SignalChip label="Compression" status="Flagged" />
                    <SignalChip label="AI screening" status="Flagged" />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
