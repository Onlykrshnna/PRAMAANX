import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { UploadCloud, CheckCircle2, FileText, ArrowUpRight } from 'lucide-react';
import { useReveal } from '../../hooks/useReveal';
import { useStepsAutoplay } from '../../hooks/useStepsAutoplay';
import { analyzeSingleFile } from '../../services/analysisService';
import { ROUTES } from '../../utils/constants';
import SectionHead from '../common/SectionHead';
import LoadingSpinner from '../common/LoadingSpinner';

export default function Steps() {
  const [ref, isRevealed] = useReveal({ threshold: 0.1 });
  const { activeStep, progress, setIsPaused, goToStep } = useStepsAutoplay(3, 3500); // 3.5s interval
  const navigate = useNavigate();

  const fileInputRef = useRef(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');

  const stepsData = [
    {
      num: '1',
      title: 'Upload your file',
      desc: 'We lock in its SHA-256 hash before touching it.',
      icon: UploadCloud,
    },
    {
      num: '2',
      title: 'Inspect the evidence',
      desc: 'Five checks run, and the heatmap shows what stood out.',
      icon: CheckCircle2,
    },
    {
      num: '3',
      title: 'Read the verdict',
      desc: 'Get a cautious, plain-English answer and a PDF report.',
      icon: FileText,
    },
  ];

  const handleFileProcess = async (file) => {
    if (!file) return;
    setErrorMsg('');
    setIsAnalyzing(true);
    try {
      const response = await analyzeSingleFile(file);
      navigate(ROUTES.RESULTS, {
        state: {
          result: response,
          type: 'single',
          filePreview: URL.createObjectURL(file),
        },
      });
    } catch (err) {
      setErrorMsg(err.message || 'Analysis failed. Redirecting to workspace...');
      setTimeout(() => {
        navigate(ROUTES.ANALYZE);
      }, 1500);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileProcess(e.dataTransfer.files[0]);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  return (
    <section
      id="how"
      ref={ref}
      className={`landing-section space-y-12 border-t border-[var(--line)] reveal-section ${
        isRevealed ? 'revealed' : ''
      }`}
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
    >
      {/* Section Head: NO eyebrows, NO gradient text */}
      <SectionHead
        title="Get a result in 3 steps"
        subtitle="No account, no setup, no waiting on a server."
      />

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        {/* Real Working Drop-Zone Card (5 cols) */}
        <div className="lg:col-span-5">
          <input
            type="file"
            ref={fileInputRef}
            onChange={(e) => e.target.files?.[0] && handleFileProcess(e.target.files[0])}
            accept="image/jpeg,image/png,image/jpg"
            className="hidden"
            aria-label="Upload evidence file"
          />

          <div
            onClick={() => !isAnalyzing && fileInputRef.current?.click()}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            className={`border-2 border-dashed border-[var(--line)] rounded-[26px] p-8 sm:p-12 text-center bg-[var(--card)] hover:border-[var(--brand)] transition-all cursor-pointer group space-y-4 select-none relative overflow-hidden shadow-xs hover:shadow-md ${
              isAnalyzing ? 'opacity-90 pointer-events-none' : ''
            }`}
          >
            {isAnalyzing ? (
              <div className="py-6 space-y-3">
                <LoadingSpinner size="lg" className="mx-auto text-[var(--brand)]" />
                <p className="font-mono text-xs font-semibold text-[var(--ink)]">
                  Executing forensic pipeline on device...
                </p>
              </div>
            ) : (
              <>
                <div className="w-14 h-14 mx-auto rounded-full bg-[var(--soft)] border border-[var(--line)] flex items-center justify-center text-[var(--brand)] group-hover:scale-105 transition-transform">
                  <UploadCloud className="w-7 h-7" />
                </div>
                <div className="space-y-1">
                  <h3 className="font-extrabold text-lg sm:text-xl text-[var(--ink)] tracking-tight">
                    Drop an image here
                  </h3>
                  <p className="text-xs sm:text-sm text-[var(--mute)] font-mono">
                    JPG or PNG. It never leaves your device.
                  </p>
                </div>
                <div className="pt-2">
                  <span className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full text-xs font-bold font-mono uppercase tracking-wider bg-[var(--soft)] text-[var(--brand)] border border-[var(--line)] group-hover:bg-[var(--brand)] group-hover:text-white transition-all">
                    <span>Browse file</span>
                    <ArrowUpRight className="w-3.5 h-3.5" />
                  </span>
                </div>
              </>
            )}

            {errorMsg && (
              <p className="text-xs font-mono text-[var(--bad)] mt-2">
                {errorMsg}
              </p>
            )}
          </div>
        </div>

        {/* 3 Steps in Real Sequence Autoplaying every 3.5s (7 cols) */}
        <div className="lg:col-span-7 space-y-4 text-left">
          {stepsData.map((step, idx) => {
            const isActive = activeStep === idx;
            const Icon = step.icon;

            return (
              <div
                key={step.num}
                onClick={() => goToStep(idx)}
                className={`relative overflow-hidden p-6 rounded-[22px] border transition-all cursor-pointer ${
                  isActive
                    ? 'border-[var(--brand)] bg-[var(--card)] shadow-md shadow-[var(--glow)]/30'
                    : 'border-[var(--line)] bg-[var(--card)]/50 hover:border-[var(--border-strong)]'
                }`}
              >
                {/* 3.5s Progress indicator line on active step */}
                {isActive && (
                  <div
                    className="absolute top-0 left-0 bottom-0 bg-[var(--brand)]/10 transition-all duration-75 pointer-events-none"
                    style={{ width: `${progress}%` }}
                  />
                )}

                <div className="relative z-10 flex items-start gap-4 sm:gap-5">
                  <div
                    className={`w-10 h-10 rounded-full font-mono text-sm font-extrabold flex items-center justify-center flex-shrink-0 transition-colors ${
                      isActive
                        ? 'bg-[var(--brand)] text-white shadow-xs'
                        : 'bg-[var(--soft)] text-[var(--mute)] border border-[var(--line)]'
                    }`}
                  >
                    {step.num}
                  </div>

                  <div className="space-y-1 flex-1">
                    <div className="flex items-center justify-between">
                      <h3 className="font-extrabold text-base sm:text-lg text-[var(--ink)] tracking-tight">
                        {step.title}
                      </h3>
                      {isActive && (
                        <Icon className="w-4 h-4 text-[var(--brand)]" />
                      )}
                    </div>
                    <p className="text-sm text-[var(--mute)] leading-relaxed">
                      {step.desc}
                    </p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
