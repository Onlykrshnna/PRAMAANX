/**
 * PRAMAANX - Architectural Semicircle Risk Gauge
 * Smooth SVG semicircle gauge showing calibrated risk score (0-100)
 * with color-coded safe/review/risk arc and accessible ARIA attributes.
 */

import { useEffect, useState } from 'react';

export default function SemicircleGauge({
  score = 0,
  maxScore = 100,
  size = 200,
  className = '',
}) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => {
      setAnimatedScore(Math.min(Math.max(score, 0), maxScore));
    }, 100);
    return () => clearTimeout(timer);
  }, [score, maxScore]);

  // Radius and arc math for semicircle
  const strokeWidth = 14;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = Math.PI * radius; // Half-circle circumference
  const strokeDashoffset = circumference - (animatedScore / maxScore) * circumference;

  const getColor = (val) => {
    if (val <= 30) return 'var(--status-low)';
    if (val <= 69) return 'var(--status-medium)';
    return 'var(--status-high)';
  };

  const currentColor = getColor(score);

  return (
    <div
      role="progressbar"
      aria-valuenow={score}
      aria-valuemin={0}
      aria-valuemax={maxScore}
      aria-label={`Risk score: ${score} out of ${maxScore}`}
      className={`relative flex flex-col items-center justify-center ${className}`}
      style={{ width: size, height: size / 2 + 30 }}
    >
      <svg
        width={size}
        height={size / 2 + 10}
        viewBox={`0 0 ${size} ${size / 2 + 10}`}
        className="overflow-visible"
      >
        {/* Background Track Arc */}
        <path
          d={`M ${strokeWidth} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth} ${size / 2}`}
          fill="none"
          stroke="var(--border-hairline)"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />

        {/* Animated Score Progress Arc */}
        <path
          d={`M ${strokeWidth} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth} ${size / 2}`}
          fill="none"
          stroke={currentColor}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className="transition-all duration-700 ease-out"
        />
      </svg>

      {/* Center Value */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-2 text-center pointer-events-none select-none">
        <div className="flex items-baseline justify-center gap-0.5">
          <span className="font-display font-extrabold text-3xl sm:text-4xl tracking-tight text-[var(--text-primary)]">
            {score}
          </span>
          <span className="font-mono text-xs text-[var(--text-muted)] font-medium">/100</span>
        </div>
      </div>
    </div>
  );
}

