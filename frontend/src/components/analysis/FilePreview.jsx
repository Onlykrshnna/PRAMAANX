/**
 * PRAMAANX - Architectural Laboratory File Preview Component
 * Displays the list of queued evidence files with image thumbnails, format icons,
 * size breakdowns, and removal actions.
 */

import {
  FileText,
  Image as ImageIcon,
  Archive,
  Table,
  Presentation,
  File,
  Trash2,
} from 'lucide-react';
import Button from '../common/Button';
import Badge from '../common/Badge';
import { formatBytes } from '../../utils/formatters';

function getFileIcon(extension, category) {
  switch (extension) {
    case '.pdf':
      return <FileText className="w-5 h-5 text-[var(--accent-cobalt)]" />;
    case '.docx':
    case '.doc':
      return <FileText className="w-5 h-5 text-indigo-400" />;
    case '.xlsx':
    case '.xls':
      return <Table className="w-5 h-5 text-emerald-500" />;
    case '.pptx':
    case '.ppt':
      return <Presentation className="w-5 h-5 text-amber-500" />;
    case '.zip':
      return <Archive className="w-5 h-5 text-amber-600" />;
    default:
      if (category === 'image') {
        return <ImageIcon className="w-5 h-5 text-purple-400" />;
      }
      return <File className="w-5 h-5 text-[var(--text-muted)]" />;
  }
}

export default function FilePreview({
  files,
  onRemoveFile,
  onClearQueue,
  disabled = false,
}) {
  if (!files || files.length === 0) {
    return null;
  }

  const totalBytes = files.reduce((acc, f) => acc + f.size, 0);

  return (
    <div className="space-y-4">
      {/* Queue Header & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 px-1">
        <div className="flex items-center gap-2.5">
          <h3 className="text-sm font-display font-bold text-[var(--text-primary)] tracking-tight">
            Selected Evidence Files
          </h3>
          <Badge variant="neutral" size="sm">
            {files.length} {files.length === 1 ? 'file' : 'files'} • {formatBytes(totalBytes)}
          </Badge>
        </div>

        <Button
          variant="ghost"
          size="sm"
          icon={Trash2}
          disabled={disabled}
          onClick={onClearQueue}
          className="text-[var(--status-high)] hover:bg-[var(--status-high-bg)] self-start sm:self-auto"
        >
          Clear Queue
        </Button>
      </div>

      {/* Files List */}
      <div className="divide-y divide-[var(--border-hairline)] rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] overflow-hidden lab-card">
        {files.map((item) => (
          <div
            key={item.id}
            className="flex items-center justify-between p-3.5 sm:p-4 hover:bg-[var(--bg-subtle)] transition-colors gap-3"
          >
            {/* Left: Thumbnail / Icon + Name + Size */}
            <div className="flex items-center gap-3.5 min-w-0">
              <div className="w-11 h-11 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)] flex items-center justify-center shrink-0 overflow-hidden shadow-2xs">
                {item.thumbnailUrl ? (
                  <img
                    src={item.thumbnailUrl}
                    alt={item.name}
                    className="w-full h-full object-cover"
                  />
                ) : (
                  getFileIcon(item.extension, item.typeCategory)
                )}
              </div>

              <div className="min-w-0">
                <p className="text-xs sm:text-sm font-semibold font-mono text-[var(--text-primary)] truncate max-w-xs sm:max-w-md">
                  {item.name}
                </p>
                <div className="flex items-center gap-2 mt-0.5 text-[11px] font-mono text-[var(--text-muted)]">
                  <span>{formatBytes(item.size)}</span>
                  <span>•</span>
                  <span className="uppercase">{item.extension.replace('.', '') || 'UNKNOWN'}</span>
                </div>
              </div>
            </div>

            {/* Right: Removal Trigger */}
            <Button
              variant="ghost"
              size="sm"
              icon={Trash2}
              disabled={disabled}
              onClick={() => onRemoveFile(item.id)}
              className="text-[var(--text-muted)] hover:text-[var(--status-high)] shrink-0"
            >
              Remove
            </Button>
          </div>
        ))}
      </div>
    </div>
  );
}
