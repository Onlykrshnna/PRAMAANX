import LoadingSpinner from './LoadingSpinner';

export default function Button({
  children,
  variant = 'primary', // 'primary' | 'dark' | 'ghost' | 'outline'
  size = 'md',
  icon: Icon,
  iconPosition = 'left',
  loading = false,
  disabled = false,
  className = '',
  type = 'button',
  onClick,
  ...props
}) {
  const baseClasses =
    'inline-flex items-center justify-center font-bold tracking-tight rounded-full cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-[var(--brand)]/30 lift-button select-none transition-all';

  const sizeClasses = {
    sm: 'text-xs px-3.5 py-1.5 gap-1.5 font-mono',
    md: 'text-sm px-5 py-2.5 gap-2',
    lg: 'text-base px-6 py-3 gap-2.5',
  };

  const variantClasses = {
    // Primary: brand purple (#5b3df5 / #8b73ff) with white text and brand shadow lift
    primary:
      'bg-[var(--brand)] text-white hover:opacity-95 shadow-md shadow-[var(--brand)]/20 border border-[var(--brand)]',
    // Dark: ink color (#16132e / #f1eeff) on bg (#f4f1ff / #0f0c24)
    dark:
      'bg-[var(--ink)] text-[var(--bg)] hover:opacity-90 shadow-sm border border-[var(--ink)]',
    // Ghost: muted text, hover soft background
    ghost:
      'bg-transparent text-[var(--mute)] hover:text-[var(--ink)] hover:bg-[var(--soft)]',
    // Outline: subtle line border
    outline:
      'bg-[var(--card)] text-[var(--ink)] border border-[var(--line)] hover:border-[var(--brand)] hover:text-[var(--brand)] shadow-xs',
    // Secondary compatibility alias
    secondary:
      'bg-[var(--soft)] text-[var(--ink)] hover:bg-[var(--line)] border border-[var(--line)]',
    accent:
      'bg-[var(--brand)] text-white hover:opacity-95 shadow-md shadow-[var(--brand)]/20 border border-[var(--brand)]',
  };

  const selectedVariant = variantClasses[variant] || variantClasses.primary;
  const selectedSize = sizeClasses[size] || sizeClasses.md;

  return (
    <button
      type={type}
      disabled={disabled || loading}
      onClick={onClick}
      className={`${baseClasses} ${selectedVariant} ${selectedSize} ${className}`}
      {...props}
    >
      {loading ? (
        <>
          <LoadingSpinner size="sm" className="mr-2" />
          <span>{children}</span>
        </>
      ) : (
        <>
          {Icon && iconPosition === 'left' && <Icon className="w-4 h-4 flex-shrink-0" />}
          <span>{children}</span>
          {Icon && iconPosition === 'right' && <Icon className="w-4 h-4 flex-shrink-0" />}
        </>
      )}
    </button>
  );
}
