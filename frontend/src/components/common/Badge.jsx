/**
 * PRAMAANX - Common Badge Component
 * Architectural laboratory status indicator supporting light and dark themes.
 */

export default function Badge({
  children,
  variant = 'neutral',
  size = 'md',
  dot = false,
  className = '',
}) {
  const sizeClasses = {
    sm: 'text-[10px] px-2 py-0.5 gap-1.5',
    md: 'text-xs px-2.5 py-0.5 gap-1.5',
    lg: 'text-sm px-3 py-1 gap-2',
  };

  const variantClasses = {
    low: 'text-[var(--status-low)] bg-[var(--status-low-bg)] border border-[var(--status-low-border)]',
    medium: 'text-[var(--status-medium)] bg-[var(--status-medium-bg)] border border-[var(--status-medium-border)]',
    high: 'text-[var(--status-high)] bg-[var(--status-high-bg)] border border-[var(--status-high-border)]',
    neutral: 'text-[var(--text-secondary)] bg-[var(--bg-subtle)] border border-[var(--border-hairline)]',
    metallic: 'text-[var(--text-primary)] bg-[var(--bg-surface)] border border-[var(--border-strong)]',
    demo: 'text-[var(--text-muted)] bg-[var(--bg-subtle)] border border-[var(--border-hairline)] font-mono tracking-wider',
  };

  const dotColors = {
    low: 'bg-[var(--status-low)]',
    medium: 'bg-[var(--status-medium)]',
    high: 'bg-[var(--status-high)]',
    neutral: 'bg-[var(--text-muted)]',
    metallic: 'bg-[var(--text-primary)]',
    demo: 'bg-[var(--text-muted)]',
  };

  return (
    <span
      className={`inline-flex items-center font-mono font-medium rounded-full ${sizeClasses[size]} ${variantClasses[variant] || variantClasses.neutral} ${className}`}
    >
      {dot && (
        <span
          className={`w-1.5 h-1.5 rounded-full ${dotColors[variant] || 'bg-[var(--text-muted)]'}`}
        />
      )}
      {children}
    </span>
  );
}
