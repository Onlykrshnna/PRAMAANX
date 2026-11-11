/**
 * PRAMAANX - Common Modal Dialog
 * Architectural modal overlay with theme variables, keyboard accessibility,
 * and focus containment. Styled with rounded-[26px] cards and design tokens.
 */

import { useEffect } from 'react';
import { X } from 'lucide-react';

export default function Modal({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  maxWidth = 'max-w-lg',
}) {
  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 overflow-y-auto"
    >
      {/* Backdrop */}
      <div
        role="presentation"
        onClick={onClose}
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
      />

      {/* Modal Dialog Plate */}
      <div
        className={`relative w-full ${maxWidth} rounded-[26px] bg-[var(--card)] border border-[var(--line)] shadow-2xl p-6 sm:p-7 z-10 space-y-4 text-[var(--ink)]`}
      >
        {/* Header */}
        <div className="flex items-start justify-between pb-3 border-b border-[var(--line)]">
          <div>
            {title && (
              <h3 className="text-base sm:text-lg font-extrabold text-[var(--ink)] tracking-tight">
                {title}
              </h3>
            )}
            {subtitle && (
              <p className="text-xs text-[var(--mute)] mt-0.5">{subtitle}</p>
            )}
          </div>

          <button
            type="button"
            onClick={onClose}
            className="w-8 h-8 rounded-full border border-[var(--line)] bg-[var(--card)] text-[var(--mute)] hover:text-[var(--ink)] hover:bg-[var(--soft)] flex items-center justify-center transition-colors cursor-pointer"
            aria-label="Close dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="text-xs text-[var(--ink)] leading-relaxed">{children}</div>
      </div>
    </div>
  );
}
