import { Check, X } from 'lucide-react';
import { useReveal } from '../../hooks/useReveal';
import SectionHead from '../common/SectionHead';
import Card from '../common/Card';

export default function Limits() {
  const [ref, isRevealed] = useReveal({ threshold: 0.1 });

  return (
    <section
      id="limits"
      ref={ref}
      className={`landing-section space-y-12 border-t border-[var(--line)] reveal-section ${isRevealed ? 'revealed' : ''
        }`}
    >
      {/* Section Head: NO eyebrows, NO gradient text */}
      <SectionHead
        title="Honest about its limits"
        subtitle="When evidence is poor, we say “Limited evidence” instead of guessing."
      />

      {/* 2 Cards Comparison */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-7 text-left">
        {/* Good at finding */}
        <Card className="border-[var(--status-low-border)] bg-[var(--status-low-bg)]/20 space-y-5" lift>
          <div className="flex items-center gap-3 text-[var(--ok)]">
            <div className="w-8 h-8 rounded-full bg-[var(--status-low-bg)] border border-[var(--status-low-border)] flex items-center justify-center">
              <Check className="w-4 h-4 text-[var(--ok)]" />
            </div>
            <h3 className="text-xl font-extrabold tracking-tight text-[var(--ink)]">
              Good at finding
            </h3>
          </div>

          <ul className="space-y-3.5 pt-1 text-sm sm:text-base text-[var(--mute)]">
            <li className="flex items-start gap-3">
              <span className="w-2 h-2 rounded-full bg-[var(--ok)] mt-2 flex-shrink-0" />
              <span className="text-[var(--ink)] font-medium">Pasted objects and splicing</span>
            </li>
            <li className="flex items-start gap-3">
              <span className="w-2 h-2 rounded-full bg-[var(--ok)] mt-2 flex-shrink-0" />
              <span className="text-[var(--ink)] font-medium">Removed or cloned regions</span>
            </li>
            <li className="flex items-start gap-3">
              <span className="w-2 h-2 rounded-full bg-[var(--ok)] mt-2 flex-shrink-0" />
              <span className="text-[var(--ink)] font-medium">Uneven compression history</span>
            </li>
          </ul>
        </Card>

        {/* Not reliable for */}
        <Card className="border-[var(--line)] bg-[var(--soft)]/40 space-y-5" lift>
          <div className="flex items-center gap-3 text-[var(--mute)]">
            <div className="w-8 h-8 rounded-full bg-[var(--card)] border border-[var(--line)] flex items-center justify-center">
              <X className="w-4 h-4 text-[var(--mute)]" />
            </div>
            <h3 className="text-xl font-extrabold tracking-tight text-[var(--ink)]">
              Not reliable for
            </h3>
          </div>

          <ul className="space-y-3.5 pt-1 text-sm sm:text-base text-[var(--mute)]">
            <li className="flex items-start gap-3">
              <span className="w-2 h-2 rounded-full bg-[var(--mute)] mt-2 flex-shrink-0" />
              <span className="text-[var(--ink)] font-medium">Color filters and brightness edits</span>
            </li>
            <li className="flex items-start gap-3">
              <span className="w-2 h-2 rounded-full bg-[var(--mute)] mt-2 flex-shrink-0" />
              <span className="text-[var(--ink)] font-medium">Images recompressed by messaging apps</span>
            </li>
            <li className="flex items-start gap-3">
              <span className="w-2 h-2 rounded-full bg-[var(--mute)] mt-2 flex-shrink-0" />
              <span className="text-[var(--ink)] font-medium">Proof of authenticity</span>
            </li>
          </ul>
        </Card>
      </div>
    </section>
  );
}
