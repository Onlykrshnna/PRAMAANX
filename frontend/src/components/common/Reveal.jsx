import { useReveal } from '../../hooks/useReveal';

export default function Reveal({
  children,
  threshold = 0.25,
  className = '',
  as: Component = 'div',
  ...props
}) {
  const [ref, isRevealed] = useReveal({ threshold });

  return (
    <Component
      ref={ref}
      className={`reveal-section ${isRevealed ? 'revealed' : ''} ${className}`}
      {...props}
    >
      {children}
    </Component>
  );
}

