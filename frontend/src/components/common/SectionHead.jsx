export default function SectionHead({
  title,
  subtitle,
  align = 'left', // 'left' | 'center'
  className = '',
  ...props
}) {
  const alignClass = align === 'center' ? 'text-center mx-auto' : 'text-left';

  return (
    <div className={`max-w-3xl space-y-3 ${alignClass} ${className}`} {...props}>
      {title && (
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold tracking-[-0.03em] text-[var(--ink)] leading-[1.1]">
          {title}
        </h2>
      )}
      {subtitle && (
        <p className="text-base sm:text-lg text-[var(--mute)] leading-relaxed">
          {subtitle}
        </p>
      )}
    </div>
  );
}

