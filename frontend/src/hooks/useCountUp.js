import { useEffect, useState } from 'react';
import { usePrefersReducedMotion } from './usePrefersReducedMotion';

/**
 * Counts up smoothly from 0 to endValue with an ease-out curve once triggered.
 * Honors prefers-reduced-motion by immediately returning endValue without animation.
 */
export function useCountUp(endValue, duration = 1200, start = true) {
  const prefersReduced = usePrefersReducedMotion();
  const [animatedCount, setAnimatedCount] = useState(0);

  useEffect(() => {
    if (prefersReduced || !start) return;

    let startTimestamp = null;
    let animationFrame;

    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setAnimatedCount(Math.round(eased * endValue));

      if (progress < 1) {
        animationFrame = requestAnimationFrame(step);
      } else {
        setAnimatedCount(endValue);
      }
    };

    animationFrame = requestAnimationFrame(step);
    return () => cancelAnimationFrame(animationFrame);
  }, [endValue, duration, start, prefersReduced]);

  if (prefersReduced) {
    return endValue;
  }

  return start ? animatedCount : 0;
}
