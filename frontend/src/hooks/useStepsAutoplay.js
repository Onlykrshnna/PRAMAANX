import { useEffect, useState, useCallback } from 'react';
import { usePrefersReducedMotion } from './usePrefersReducedMotion';

/**
 * Autoplay timer hook that advances through steps sequentially.
 * Supports pause on hover, manual selection, and honors prefers-reduced-motion.
 */
export function useStepsAutoplay(stepCount = 3, interval = 4500) {
  const prefersReduced = usePrefersReducedMotion();
  const [activeStep, setActiveStep] = useState(0);
  const [isPaused, setIsPaused] = useState(false);
  const [progress, setProgress] = useState(0);

  const goToStep = useCallback((stepIndex) => {
    setActiveStep(stepIndex);
    setProgress(0);
  }, []);

  useEffect(() => {
    if (prefersReduced || isPaused) return;

    const tickInterval = 50;
    const increment = (tickInterval / interval) * 100;

    const timer = setInterval(() => {
      setProgress((prev) => {
        if (prev + increment >= 100) {
          setActiveStep((curr) => (curr + 1) % stepCount);
          return 0;
        }
        return prev + increment;
      });
    }, tickInterval);

    return () => clearInterval(timer);
  }, [prefersReduced, isPaused, stepCount, interval]);

  return {
    activeStep,
    progress,
    isPaused,
    setIsPaused,
    goToStep,
  };
}
