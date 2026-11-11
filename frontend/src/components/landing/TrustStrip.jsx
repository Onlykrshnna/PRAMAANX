import { ShieldCheck, Radio, FileCheck, Layers } from 'lucide-react';
import { useReveal } from '../../hooks/useReveal';
import Pill from '../common/Pill';

export default function TrustStrip() {
  const [ref, isRevealed] = useReveal({ threshold: 0.1 });

  return (
    <section
      ref={ref}
      className={`py-12 border-y border-[var(--line)] bg-[var(--soft)]/30 transition-all duration-700 reveal-section ${
        isRevealed ? 'revealed' : ''
      }`}
    >
      <div className="max-w-[1160px] mx-auto px-6 space-y-5 text-center">
        <p className="text-xs font-mono font-semibold uppercase tracking-widest text-[var(--mute)]">
          Built for evidence that has to stay private
        </p>

        <div className="flex flex-wrap items-center justify-center gap-3 sm:gap-4 font-mono text-xs sm:text-sm">
          <Pill icon={ShieldCheck} variant="default" size="md">
            100% on-device
          </Pill>
          <Pill icon={Radio} variant="default" size="md">
            Zero telemetry
          </Pill>
          <Pill icon={FileCheck} variant="default" size="md">
            SHA-256 custody
          </Pill>
          <Pill icon={Layers} variant="default" size="md">
            Open primitives
          </Pill>
        </div>
      </div>
    </section>
  );
}
