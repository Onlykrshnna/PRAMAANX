export default function Card({
  children,
  title,
  subtitle,
  action,
  headerIcon: HeaderIcon,
  headerBadge,
  elevated = false,
  lift = false,
  className = '',
  bodyClassName = '',
  onClick,
  ...props
}) {
  const bgClass = elevated ? 'bg-[var(--card)] shadow-lg shadow-[var(--glow)]/30' : 'bg-[var(--card)]';
  const liftClass = lift ? 'lift-card' : '';
  const interactiveClass = onClick
    ? 'cursor-pointer hover:border-[var(--brand)] transition-all'
    : '';

  return (
    <div
      onClick={onClick}
      className={`rounded-[26px] border border-[var(--line)] ${bgClass} ${liftClass} ${interactiveClass} ${className}`}
      {...props}
    >
      {(title || action || HeaderIcon || headerBadge) && (
        <div className="flex items-center justify-between px-6 py-5 border-b border-[var(--line)]">
          <div className="flex items-center gap-3">
            {HeaderIcon && (
              <div className="p-2.5 rounded-xl bg-[var(--soft)] border border-[var(--line)] text-[var(--ink)]">
                <HeaderIcon className="w-4 h-4 text-[var(--brand)]" />
              </div>
            )}
            <div>
              <div className="flex items-center gap-2">
                {title && (
                  <h3 className="text-base font-bold tracking-tight text-[var(--ink)]">
                    {title}
                  </h3>
                )}
                {headerBadge}
              </div>
              {subtitle && (
                <p className="text-xs text-[var(--mute)] mt-0.5">{subtitle}</p>
              )}
            </div>
          </div>
          {action && <div className="flex items-center gap-2">{action}</div>}
        </div>
      )}
      <div className={bodyClassName || 'p-6 sm:p-8'}>{children}</div>
    </div>
  );
}
