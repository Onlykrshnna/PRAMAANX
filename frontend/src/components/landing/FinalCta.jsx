import { useNavigate } from 'react-router-dom';
import { ArrowUpRight } from 'lucide-react';
import { useReveal } from '../../hooks/useReveal';
import { ROUTES } from '../../utils/constants';

export default function FinalCta() {
  const [ref, isRevealed] = useReveal({ threshold: 0.1 });
  const navigate = useNavigate();

  return (
    <footer
      ref={ref}
      className={`landing-section space-y-16 border-t border-[var(--line)] reveal-section ${
        isRevealed ? 'revealed' : ''
      }`}
    >
      {/* Deep Purple Radial Gradient CTA Block */}
      <div
        className="max-w-[1160px] mx-auto rounded-[26px] p-10 sm:p-16 text-center text-white relative overflow-hidden shadow-2xl shadow-[var(--glow)]/30 border border-white/10"
        style={{
          background: 'radial-gradient(circle at center, #2e1d7a 0%, #150f38 100%)',
        }}
      >
        <div className="max-w-2xl mx-auto space-y-5 relative z-10">
          <h2 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold tracking-[-0.03em] leading-[1.1] text-white">
            Check your first image now
          </h2>
          <p className="text-base sm:text-lg text-purple-200">
            Free, private, and readable by everyone.
          </p>
          <div className="pt-3">
            <button
              type="button"
              onClick={() => navigate(ROUTES.ANALYZE)}
              className="inline-flex items-center gap-2.5 px-7 py-3.5 rounded-full text-sm font-bold uppercase tracking-wider bg-white text-[#150f38] hover:bg-purple-50 lift-button shadow-lg cursor-pointer"
            >
              <span>Analyze evidence</span>
              <ArrowUpRight className="w-4 h-4 text-[#150f38]" />
            </button>
          </div>
        </div>
      </div>

      {/* Compact Minimal Footer */}
      <div className="max-w-[1160px] mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-[var(--mute)] text-center sm:text-left">
        <div>
          © 2026 PRAMAANX. Built for digital forensics education and research.
        </div>
        <div>
          Triage indicators only, not courtroom testimony.
        </div>
      </div>
    </footer>
  );
}
