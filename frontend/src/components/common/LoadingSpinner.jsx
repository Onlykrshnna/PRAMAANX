/**
 * PRAMAANX - Common Loading Spinner
 * Architectural laboratory spinner with theme variables.
 */

export default function LoadingSpinner({ size = 'md', className = '' }) {
  const sizeClasses = {
    xs: 'w-3 h-3 border',
    sm: 'w-4 h-4 border',
    md: 'w-5 h-5 border-2',
    lg: 'w-8 h-8 border-2',
  };

  return (
    <div
      role="status"
      aria-label="Loading"
      className={`inline-block animate-spin rounded-full border-[var(--border-hairline)] border-t-[var(--accent-cobalt)] ${sizeClasses[size]} ${className}`}
    />
  );
}
