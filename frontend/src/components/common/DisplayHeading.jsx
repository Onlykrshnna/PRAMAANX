/**
 * PRAMAANX - Editorial Display Heading Component
 * Implements massive, high-contrast, architectural typography (64-110px responsive).
 */

export default function DisplayHeading({
  kicker,
  children,
  subtitle,
  align = 'left',
  size = 'display', // 'display' | 'xl' | 'lg'
  className = '',
}) {
  const sizeClasses = {
    display: 'text-4xl sm:text-6xl md:text-7xl lg:text-8xl leading-[1.02]',
    xl: 'text-3xl sm:text-5xl md:text-6xl leading-[1.05]',
    lg: 'text-2xl sm:text-4xl md:text-5xl leading-[1.1]',
  };

  const alignClasses = {
    left: 'text-left',
    center: 'text-center mx-auto',
    right: 'text-right ml-auto',
  };

  return (
    <div className={`space-y-3 ${alignClasses[align]} ${className}`}>
      {kicker && (
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-md text-[11px] font-mono font-semibold uppercase tracking-widest text-[var(--accent-cobalt)] bg-[var(--accent-subtle)] border border-[var(--accent-border)]">
          {kicker}
        </div>
      )}
      <h1 className={`font-display font-extrabold tracking-tight text-[var(--text-primary)] ${sizeClasses[size]}`}>
        {children}
      </h1>
      {subtitle && (
        <p className="text-base sm:text-lg md:text-xl text-[var(--text-secondary)] font-normal max-w-2xl leading-relaxed">
          {subtitle}
        </p>
      )}
    </div>
  );
}

