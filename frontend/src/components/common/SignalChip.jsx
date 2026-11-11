import { CheckCircle2, AlertTriangle, HelpCircle, XCircle } from 'lucide-react';

export default function SignalChip({
  label,
  status = 'Passed', // 'Passed' | 'Flagged' | 'Not performed' | 'Error'
  onClick,
  className = '',
  active = false,
}) {
  const isPassed = status === 'Passed';
  const isFlagged = status === 'Flagged';
  const isError = status === 'Error';

  const StatusIcon = isPassed
    ? CheckCircle2
    : isFlagged
    ? AlertTriangle
    : isError
    ? XCircle
    : HelpCircle;

  const colorStyles = isPassed
    ? 'text-[var(--ok)] bg-[var(--status-low-bg)] border-[var(--status-low-border)]'
    : isFlagged
    ? 'text-[var(--warn)] bg-[var(--status-medium-bg)] border-[var(--status-medium-border)] font-semibold'
    : isError
    ? 'text-[var(--bad)] bg-[var(--status-high-bg)] border-[var(--status-high-border)] font-semibold'
    : 'text-[var(--mute)] bg-[var(--soft)] border-[var(--line)]';

  const interactiveStyles = onClick
    ? 'cursor-pointer hover:border-[var(--brand)] hover:shadow-xs active:scale-95'
    : '';

  const activeStyles = active ? 'ring-2 ring-[var(--brand)] ring-offset-1' : '';

  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono border transition-all ${colorStyles} ${interactiveStyles} ${activeStyles} ${className}`}
    >
      <StatusIcon className="w-3.5 h-3.5 flex-shrink-0" />
      <span className="text-[var(--ink)] font-sans font-medium">{label}</span>
      <span className="text-[11px] uppercase tracking-wider opacity-90">{status}</span>
    </button>
  );
}

