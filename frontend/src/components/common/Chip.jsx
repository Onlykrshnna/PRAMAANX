export default function Chip({
  children,
  icon: Icon,
  active = false,
  onClick,
  className = '',
  ...props
}) {
  const interactiveClass = onClick
    ? 'cursor-pointer hover:border-[var(--brand)] hover:text-[var(--brand)] active:scale-95'
    : '';

  const activeClass = active
    ? 'bg-[var(--brand)] text-white border-[var(--brand)] shadow-sm'
    : 'bg-[var(--card)] text-[var(--ink)] border-[var(--line)] shadow-xs';

  return (
    <div
      onClick={onClick}
      className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs sm:text-sm font-medium border select-none transition-all ${activeClass} ${interactiveClass} ${className}`}
      {...props}
    >
      {Icon && <Icon className="w-3.5 h-3.5 flex-shrink-0" />}
      <span>{children}</span>
    </div>
  );
}

