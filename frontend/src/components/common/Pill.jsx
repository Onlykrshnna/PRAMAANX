export default function Pill({
  children,
  icon: Icon,
  variant = 'default', // 'default' | 'ok' | 'warn' | 'bad' | 'brand' | 'soft'
  size = 'md',
  className = '',
  ...props
}) {
  const sizeClasses = {
    sm: 'text-xs px-3 py-1 gap-1.5 font-mono',
    md: 'text-sm px-4 py-1.5 gap-2 font-medium',
    lg: 'text-base px-5 py-2 gap-2.5 font-semibold',
  };

  const variantClasses = {
    default:
      'bg-[var(--card)] text-[var(--ink)] border border-[var(--line)] shadow-xs',
    soft:
      'bg-[var(--soft)] text-[var(--ink)] border border-[var(--line)]',
    brand:
      'bg-[var(--soft)] text-[var(--brand)] border border-[var(--line)]',
    ok:
      'bg-[var(--status-low-bg)] text-[var(--ok)] border border-[var(--status-low-border)]',
    warn:
      'bg-[var(--status-medium-bg)] text-[var(--warn)] border border-[var(--status-medium-border)]',
    bad:
      'bg-[var(--status-high-bg)] text-[var(--bad)] border border-[var(--status-high-border)]',
  };

  const selectedSize = sizeClasses[size] || sizeClasses.md;
  const selectedVariant = variantClasses[variant] || variantClasses.default;

  return (
    <span
      className={`inline-flex items-center rounded-full select-none ${selectedSize} ${selectedVariant} ${className}`}
      {...props}
    >
      {Icon && <Icon className="w-4 h-4 flex-shrink-0" />}
      <span>{children}</span>
    </span>
  );
}

