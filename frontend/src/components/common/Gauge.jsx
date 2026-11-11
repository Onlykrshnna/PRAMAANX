import { usePrefersReducedMotion } from '../../hooks/usePrefersReducedMotion';

export default function Gauge({
  score = 0,
  size = 200,
  showLabel = true,
  riskLabel = '',
  className = '',
}) {
  const prefersReduced = usePrefersReducedMotion();
  const clampedScore = Math.max(0, Math.min(100, Number(score) || 0));

  // Semicircle dimensions: radius 90, circumference = pi * r = ~282.74
  const radius = 90;
  const strokeWidth = 14;
  const circumference = Math.PI * radius; // 282.74
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  // Determine color based on calibrated ranges:
  // <35 => ok (#0f9d58 / #3ed283), 35-65 => warn (#d98200 / #f0a93a), >65 => bad (#d93f3f / #ff7070)
  const strokeColor =
    clampedScore > 65
      ? 'var(--bad)'
      : clampedScore >= 35
      ? 'var(--warn)'
      : 'var(--ok)';

  return (
    <div
      role="meter"
      aria-valuenow={clampedScore}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={`Risk score: ${clampedScore} out of 100`}
      className={`relative flex flex-col items-center justify-center select-none ${className}`}
      style={{ width: size, height: size * 0.65 }}
    >
      <svg
        viewBox="0 0 220 125"
        className="w-full h-full overflow-visible"
      >
        <defs>
          <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="var(--ok)" />
            <stop offset="50%" stopColor="var(--warn)" />
            <stop offset="100%" stopColor="var(--bad)" />
          </linearGradient>
        </defs>

        {/* Background Track Arc */}
        <path
          d="M 20 110 A 90 90 0 0 1 200 110"
          fill="none"
          stroke="var(--line)"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />

        {/* Active Animated Score Arc */}
        <path
          d="M 20 110 A 90 90 0 0 1 200 110"
          fill="none"
          stroke={strokeColor}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          style={{
            transition: prefersReduced
              ? 'none'
              : 'stroke-dashoffset 1.6s cubic-bezier(0.16, 1, 0.3, 1), stroke 0.4s ease',
          }}
        />
      </svg>

      {/* Center Score Readout */}
      {showLabel && (
        <div className="absolute inset-0 flex flex-col items-center justify-end pb-1 pointer-events-none">
          <span className="font-mono text-3xl sm:text-4xl font-extrabold text-[var(--ink)] tracking-tight">
            {Math.round(clampedScore)}
          </span>
          <span className="text-[11px] font-mono text-[var(--mute)] uppercase tracking-wider -mt-0.5">
            / 100 Risk
          </span>
          {riskLabel && (
            <span
              className="mt-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider"
              style={{
                backgroundColor: 'var(--soft)',
                color: strokeColor,
                border: '1px solid var(--line)',
              }}
            >
              {riskLabel}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

