/**
 * PRAMAANX - TechnicalData Component
 * Displays cryptographic hashes, byte offsets, and hex values with click-to-copy,
 * monospaced typography, and accessible copy notification.
 */

import { useState } from 'react';
import { Copy, Check } from 'lucide-react';

export default function TechnicalData({
  label,
  value,
  truncate = false,
  copyable = true,
  className = '',
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    if (!copyable || !value) return;
    try {
      await navigator.clipboard.writeText(String(value));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback if clipboard API is blocked
    }
  };

  const displayValue = truncate && typeof value === 'string' && value.length > 20
    ? `${value.slice(0, 10)}...${value.slice(-10)}`
    : value;

  return (
    <div className={`inline-flex items-center gap-2 p-1.5 px-2.5 rounded-md border border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-xs font-mono ${className}`}>
      {label && (
        <span className="text-[10px] uppercase font-bold text-[var(--text-muted)] tracking-wider">
          {label}:
        </span>
      )}
      <span className="font-semibold text-[var(--text-primary)] select-all truncate">
        {displayValue}
      </span>
      {copyable && (
        <button
          type="button"
          onClick={handleCopy}
          className="p-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-surface)] transition-colors cursor-pointer shrink-0"
          title="Copy value to clipboard"
          aria-label={`Copy ${label || 'value'}`}
        >
          {copied ? <Check className="w-3 h-3 text-[var(--status-low)]" /> : <Copy className="w-3 h-3" />}
        </button>
      )}
    </div>
  );
}

