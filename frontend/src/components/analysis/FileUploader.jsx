/**
 * PRAMAANX - Architectural Laboratory File Uploader
 * Precision evidence dropzone supporting drag-and-drop, format inspection,
 * keyboard accessibility, and capacity limits.
 */

import { useState, useRef } from 'react';
import { UploadCloud, FolderOpen, Archive } from 'lucide-react';
import Button from '../common/Button';
import { FILE_ACCEPT_STRING, FORENSIC_LIMITS } from '../../utils/constants';

const FORMAT_TAGS = [
  'PDF',
  'DOCX',
  'XLSX',
  'PPTX',
  'DOC',
  'XLS',
  'PPT',
  'JPG',
  'JPEG',
  'PNG',
  'ZIP',
];

export default function FileUploader({ onFilesSelected, disabled = false }) {
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled) {
      setIsDragOver(true);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!disabled && !isDragOver) {
      setIsDragOver(true);
    }
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    if (disabled) return;

    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      onFilesSelected(e.dataTransfer.files);
    }
  };

  const handleInputChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      onFilesSelected(e.target.files);
      e.target.value = '';
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInputRef.current?.click();
    }
  };

  return (
    <div className="space-y-4">
      {/* Dropzone Container */}
      <div
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-label="Upload evidence files by drag and drop or browsing"
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onKeyDown={handleKeyDown}
        onClick={() => !disabled && fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-xl p-8 sm:p-14 text-center transition-all duration-200 cursor-pointer focus:outline-none focus:ring-2 focus:ring-[var(--accent-cobalt)]/40 lab-card ${
          isDragOver
            ? 'border-[var(--accent-cobalt)] bg-[var(--accent-subtle)] scale-[0.995]'
            : 'border-[var(--border-strong)] bg-[var(--bg-surface)] hover:border-[var(--border-interactive)] hover:bg-[var(--bg-subtle)]'
        } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
      >
        {/* Hidden File Input */}
        <input
          ref={fileInputRef}
          type="file"
          multiple
          accept={FILE_ACCEPT_STRING}
          onChange={handleInputChange}
          disabled={disabled}
          className="hidden"
          aria-hidden="true"
        />

        {/* Center Intake Graphic & Instructions */}
        <div className="max-w-md mx-auto space-y-4">
          <div className="w-14 h-14 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)] flex items-center justify-center mx-auto text-[var(--accent-cobalt)] shadow-2xs">
            <UploadCloud className="w-7 h-7" />
          </div>

          <div className="space-y-1">
            <h3 className="text-base sm:text-lg font-display font-bold text-[var(--text-primary)]">
              Drop digital evidence files to inspect
            </h3>
            <p className="text-xs text-[var(--text-muted)] font-mono leading-relaxed">
              Select a single file, batch of up to {FORENSIC_LIMITS.MAX_BATCH_FILES} files, or a ZIP archive
            </p>
          </div>

          <div className="pt-2 flex items-center justify-center gap-3">
            <Button
              variant="secondary"
              size="sm"
              icon={FolderOpen}
              disabled={disabled}
              onClick={(e) => {
                e.stopPropagation();
                fileInputRef.current?.click();
              }}
            >
              Browse Files
            </Button>
          </div>
        </div>

        {/* Capacity / Intake Specification Footer */}
        <div className="mt-8 pt-4 border-t border-[var(--border-hairline)] flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-[11px] font-mono text-[var(--text-muted)]">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-cobalt)]" />
            <span>Single: 20 MB max</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent-cobalt)]" />
            <span>Batch: Up to 10 files (100 MB total)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--status-medium)]" />
            <Archive className="w-3.5 h-3.5 text-[var(--status-medium)]" />
            <span>ZIP Archives: Screened via sandbox</span>
          </div>
        </div>
      </div>

      {/* Format Matrix Tag Pills */}
      <div className="flex flex-wrap items-center justify-center gap-1.5 pt-1">
        <span className="text-[10px] uppercase font-mono font-bold text-[var(--text-muted)] tracking-wider mr-1">
          Accepted Containers:
        </span>
        {FORMAT_TAGS.map((tag) => (
          <span
            key={tag}
            className="px-2 py-0.5 rounded text-[10px] font-mono font-medium border border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-secondary)]"
          >
            {tag}
          </span>
        ))}
      </div>
    </div>
  );
}
