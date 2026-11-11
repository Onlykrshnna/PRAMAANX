import { useReveal } from '../../hooks/useReveal';
import { useCountUp } from '../../hooks/useCountUp';
import SectionHead from '../common/SectionHead';
import Card from '../common/Card';

export default function Stats() {
  const [ref, isRevealed] = useReveal({ threshold: 0.15 });

  // Count-up hooks with ~260ms per step
  const stat1 = useCountUp(5, 1300, isRevealed);
  const stat2 = useCountUp(0, 500, isRevealed);
  const stat3 = useCountUp(2, 600, isRevealed);
  const stat4 = useCountUp(4, 1100, isRevealed);

  return (
    <section
      id="why"
      ref={ref}
      className={`landing-section space-y-12 border-t border-[var(--line)] reveal-section ${
        isRevealed ? 'revealed' : ''
      }`}
    >
      {/* Section Head: NO eyebrows, NO gradient text */}
      <SectionHead
        title="Why people trust PRAMAANX"
        subtitle="Designed to be honest about what it knows."
      />

      {/* 4 Stat Cards Grid (Hover lifts 8px) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Stat 1 */}
        <Card lift className="space-y-3 text-left">
          <div className="font-mono text-5xl sm:text-6xl font-extrabold text-[var(--ink)] tracking-tight">
            {stat1}
          </div>
          <p className="text-sm font-medium text-[var(--mute)] leading-snug">
            Automated checks on every file
          </p>
        </Card>

        {/* Stat 2 */}
        <Card lift className="space-y-3 text-left">
          <div className="font-mono text-5xl sm:text-6xl font-extrabold text-[var(--ink)] tracking-tight">
            {stat2}
          </div>
          <p className="text-sm font-medium text-[var(--mute)] leading-snug">
            Bytes of your evidence sent to a cloud
          </p>
        </Card>

        {/* Stat 3 */}
        <Card lift className="space-y-3 text-left">
          <div className="font-mono text-5xl sm:text-6xl font-extrabold text-[var(--ink)] tracking-tight">
            {stat3}
          </div>
          <p className="text-sm font-medium text-[var(--mute)] leading-snug">
            Views: plain English and full technical detail
          </p>
        </Card>

        {/* Stat 4 */}
        <Card lift className="space-y-3 text-left">
          <div className="font-mono text-5xl sm:text-6xl font-extrabold text-[var(--ink)] tracking-tight">
            {stat4}
          </div>
          <p className="text-sm font-medium text-[var(--mute)] leading-snug">
            Verdict levels, including “Limited evidence”
          </p>
        </Card>
      </div>
    </section>
  );
}
