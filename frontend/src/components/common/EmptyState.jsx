/**
 * PRAMAANX - Common Empty State Component
 * Architectural laboratory placeholder with theme variables.
 */

import Button from './Button';

export default function EmptyState({
  icon: Icon,
  title,
  description,
  actionLabel,
  actionIcon,
  onAction,
  className = '',
}) {
  return (
    <div
      className={`flex flex-col items-center justify-center p-8 sm:p-12 text-center rounded-xl border border-dashed border-[var(--border-strong)] bg-[var(--bg-subtle)] ${className}`}
    >
      {Icon && (
        <div className="w-12 h-12 rounded-xl bg-[var(--bg-surface)] border border-[var(--border-hairline)] flex items-center justify-center text-[var(--text-muted)] mb-3 shadow-2xs">
          <Icon className="w-6 h-6 text-[var(--accent-cobalt)]" />
        </div>
      )}
      {title && (
        <h4 className="text-sm font-semibold font-display text-[var(--text-primary)] mb-1">
          {title}
        </h4>
      )}
      {description && (
        <p className="text-xs text-[var(--text-muted)] max-w-sm mb-4 leading-relaxed">
          {description}
        </p>
      )}
      {actionLabel && onAction && (
        <Button
          variant="secondary"
          size="sm"
          icon={actionIcon}
          onClick={onAction}
        >
          {actionLabel}
        </Button>
      )}
    </div>
  );
}
