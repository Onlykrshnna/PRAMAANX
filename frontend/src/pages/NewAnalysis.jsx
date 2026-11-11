/**
 * PRAMAANX - Architectural Laboratory Evidence Intake Workspace
 * Multi-engine ingestion pipeline connected to FastAPI (/analyze, /analyze/batch, /analyze/archive)
 * with optional persistent Investigation & Evidence Vault association.
 */

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import PageHeader from '../components/layout/PageHeader';
import Badge from '../components/common/Badge';
import Button from '../components/common/Button';
import FileUploader from '../components/analysis/FileUploader';
import FilePreview from '../components/analysis/FilePreview';
import { useUpload } from '../hooks/useUpload';
import {
  analyzeSingleFile,
  analyzeBatch,
  analyzeArchive,
} from '../services/analysisService';
import {
  getInvestigations,
  createInvestigation,
  uploadEvidenceToCase,
} from '../services/api';
import { ROUTES } from '../utils/constants';
import {
  FileSearch,
  AlertCircle,
  X,
  Lock,
  Cpu,
  FolderArchive,
} from 'lucide-react';
import { formatBytes } from '../utils/formatters';

export default function NewAnalysis() {
  const navigate = useNavigate();
  const {
    files,
    errors,
    addFiles,
    removeFile,
    clearQueue,
    addError,
    removeError,
    clearErrors,
    totalCount,
    totalBytes,
    hasFiles,
    isFull,
  } = useUpload();

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(null);
  const [analysisStage, setAnalysisStage] = useState('');

  // Investigation persistence state
  const [caseMode, setCaseMode] = useState('session'); // 'session' | 'existing' | 'new'
  const [openCases, setOpenCases] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [newCaseTitle, setNewCaseTitle] = useState('');
  const [newCaseInvestigator, setNewCaseInvestigator] = useState('');

  useEffect(() => {
    getInvestigations({ status: 'open' })
      .then((res) => {
        const list = res.investigations || [];
        setOpenCases(list);
        if (list.length > 0) {
          setSelectedCaseId(list[0].id);
        }
      })
      .catch(() => setOpenCases([]));
  }, []);

  const handleStartAnalysis = async () => {
    if (!hasFiles || isSubmitting) return;

    // Check for mixed ZIP and non-ZIP files in the queue
    const zipFiles = files.filter((f) => f.extension === '.zip');
    const nonZipFiles = files.filter((f) => f.extension !== '.zip');

    if (zipFiles.length > 0 && nonZipFiles.length > 0) {
      addError(
        'ZIP archives must be analyzed individually. Please upload either a single ZIP archive or up to 10 standard documents/images.'
      );
      return;
    }

    if (zipFiles.length > 1) {
      addError(
        'Only one ZIP archive can be screened at a time. Please select a single ZIP file.'
      );
      return;
    }

    if (caseMode === 'new' && !newCaseTitle.trim()) {
      addError('Please provide a Case Title to establish a new investigation.');
      return;
    }

    setIsSubmitting(true);
    setUploadProgress(10);
    setAnalysisStage('Streaming files to local forensic sandbox...');

    try {
      // Determine if saving to an investigation
      let targetCaseId = null;
      if (caseMode === 'existing' && selectedCaseId) {
        targetCaseId = selectedCaseId;
      } else if (caseMode === 'new' && newCaseTitle.trim()) {
        const created = await createInvestigation({
          title: newCaseTitle.trim(),
          investigator: newCaseInvestigator.trim() || 'Forensic Examiner',
          priority: 'medium',
        });
        targetCaseId = created.id;
      }

      // If associated with a case and single file, ingest directly into vault
      if (targetCaseId && files.length === 1 && zipFiles.length === 0) {
        setAnalysisStage('Acquiring evidence into persistent vault and executing screening...');
        const response = await uploadEvidenceToCase(
          targetCaseId,
          files[0].file,
          (percent) => setUploadProgress(percent)
        );

        navigate(ROUTES.RESULTS, {
          state: {
            result: {
              file: response.file,
              analysis: response.analysis,
            },
            type: 'single',
            caseId: targetCaseId,
            filePreview: files[0]?.thumbnailUrl,
          },
        });
        return;
      }

      // Default Session Pipeline
      if (zipFiles.length === 1) {
        // ZIP Archive Analysis
        const response = await analyzeArchive(zipFiles[0].file, (percent) => {
          setUploadProgress(percent);
          if (percent >= 100) {
            setAnalysisStage('Pre-extraction Zip Slip & Bomb screening in progress...');
          }
        });

        try {
          sessionStorage.setItem('pramaanx_latest_archive', JSON.stringify({
            result: response,
            type: 'archive',
            caseId: targetCaseId,
            timestamp: Date.now(),
          }));
        } catch {
          // Ignore
        }

        navigate(ROUTES.RESULTS, {
          state: {
            result: response,
            type: 'archive',
            caseId: targetCaseId,
          },
        });
      } else if (files.length === 1) {
        // Single File Analysis
        const response = await analyzeSingleFile(files[0].file, (percent) => {
          setUploadProgress(percent);
          if (percent >= 100) {
            setAnalysisStage('Evaluating metadata, static structures & neural tamper maps...');
          }
        });

        const singleState = {
          result: response,
          type: 'single',
          caseId: targetCaseId,
          filePreview: files[0]?.thumbnailUrl,
        };

        try {
          sessionStorage.setItem('pramaanx_latest_single', JSON.stringify({
            ...singleState,
            timestamp: Date.now(),
          }));
        } catch {
          // Ignore
        }

        navigate(ROUTES.RESULTS, {
          state: singleState,
        });
      } else {
        // Batch Analysis (2 to 10 files)
        const rawFiles = files.map((item) => item.file);
        const response = await analyzeBatch(rawFiles, (percent) => {
          setUploadProgress(percent);
          if (percent >= 100) {
            setAnalysisStage('Running concurrent multi-engine inspection across batch...');
          }
        });

        const batchId = `batch_${Date.now()}`;
        const filePreviews = {};
        files.forEach((item) => {
          if (item.name && item.thumbnailUrl) {
            filePreviews[item.name] = item.thumbnailUrl;
          }
        });

        const batchPayload = {
          result: response,
          type: 'batch',
          batchId,
          caseId: targetCaseId,
          filePreviews,
        };

        try {
          sessionStorage.setItem(`pramaanx_batch_${batchId}`, JSON.stringify({
            ...batchPayload,
            timestamp: Date.now(),
          }));
          sessionStorage.setItem('pramaanx_latest_batch', batchId);
        } catch {
          // Ignore
        }

        navigate(`/analysis/results/batch/${batchId}`, {
          state: batchPayload,
        });
      }
    } catch (err) {
      let friendlyMessage = err.message || 'Forensic analysis encountered an unexpected error.';

      if (err.status === 413 || err.code === 'AGGREGATE_BATCH_SIZE_EXCEEDED') {
        friendlyMessage =
          err.message || 'File size exceeds maximum allowable forensic limit (20 MB single / 100 MB aggregate).';
      } else if (err.status === 415 || err.code === 'UNSUPPORTED_FILE_FORMAT') {
        friendlyMessage =
          err.message || 'The uploaded file format is not supported for forensic inspection.';
      } else if (err.code === 'NETWORK_ERROR' || (err.message && err.message.includes('Network'))) {
        friendlyMessage =
          'Unable to communicate with the local PRAMAANX API (port 8000). Please verify that the backend server is running.';
      }

      addError(friendlyMessage);
    } finally {
      setIsSubmitting(false);
      setUploadProgress(null);
      setAnalysisStage('');
    }
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Page Header */}
      <PageHeader
        title="Evidence Intake & Analysis"
        subtitle="Submit documents, images, or archives to inspect byte signatures, internal structures, and tamper probabilities."
        badge={
          <Badge variant="neutral" size="sm">
            EVIDENCE GATEWAY
          </Badge>
        }
      />

      {/* Unified Forensic Workflow Modes Guide */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
        <div className="p-3.5 rounded-xl bg-[var(--bg-surface)] border border-[var(--border-hairline)] space-y-1 lab-card">
          <span className="font-bold text-[var(--text-primary)] flex items-center gap-1.5 font-display">
            <span className="w-2 h-2 rounded-full bg-[var(--accent-cobalt)]" />
            Single-File Dissection
          </span>
          <p className="text-[var(--text-muted)] text-[11px] leading-relaxed">
            Deep forensic analysis of 1 document or image with full metadata, Shannon entropy, and Grad-CAM maps.
          </p>
        </div>

        <div className="p-3.5 rounded-xl bg-[var(--bg-surface)] border border-[var(--border-hairline)] space-y-1 lab-card">
          <span className="font-bold text-[var(--text-primary)] flex items-center gap-1.5 font-display">
            <span className="w-2 h-2 rounded-full bg-[var(--status-low)]" />
            Batch Triage (2–10)
          </span>
          <p className="text-[var(--text-muted)] text-[11px] leading-relaxed">
            Concurrent multi-file triage across mixed formats with independent failure isolation.
          </p>
        </div>

        <div className="p-3.5 rounded-xl bg-[var(--bg-surface)] border border-[var(--border-hairline)] space-y-1 lab-card">
          <span className="font-bold text-[var(--text-primary)] flex items-center gap-1.5 font-display">
            <span className="w-2 h-2 rounded-full bg-[var(--status-medium)]" />
            Hardened ZIP Screening
          </span>
          <p className="text-[var(--text-muted)] text-[11px] leading-relaxed">
            Pre-extraction Zip Slip & Bomb screening protecting your workstation before extracted inspection.
          </p>
        </div>
      </div>

      {/* Validation Error Alerts */}
      {errors.length > 0 && (
        <div
          role="alert"
          aria-live="assertive"
          className="rounded-xl border border-[var(--status-high-border)] bg-[var(--status-high-bg)] p-4 sm:p-5 space-y-2"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-[var(--status-high)]">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>Intake Exceptions ({errors.length})</span>
            </div>
            <button
              type="button"
              onClick={clearErrors}
              className="text-xs font-mono text-[var(--status-high)] hover:underline font-medium cursor-pointer"
            >
              Dismiss all
            </button>
          </div>

          <ul className="space-y-1.5 pt-1 text-xs text-[var(--status-high)]">
            {errors.map((err, idx) => (
              <li
                key={idx}
                className="flex items-start justify-between gap-2 p-2 rounded-md bg-[var(--bg-surface)] border border-[var(--status-high-border)]"
              >
                <span className="font-mono text-xs">{err}</span>
                <button
                  type="button"
                  onClick={() => removeError(idx)}
                  className="text-[var(--status-high)] hover:opacity-75 p-0.5 rounded cursor-pointer"
                  aria-label="Dismiss this notification"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Primary Drag & Drop Uploader */}
      <FileUploader onFilesSelected={addFiles} disabled={isFull || isSubmitting} />

      {/* Selected Files Queue Preview */}
      {hasFiles && (
        <div className="space-y-6 pt-2">
          <FilePreview
            files={files}
            onRemoveFile={removeFile}
            onClearQueue={clearQueue}
            disabled={isSubmitting}
          />

          {/* Optional Investigation Persistence Card */}
          <div className="p-5 rounded-xl bg-[var(--bg-surface)] border border-[var(--border-hairline)] space-y-4 lab-card">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-[var(--text-primary)] flex items-center gap-2">
                <FolderArchive className="w-4 h-4 text-[var(--accent-cobalt)]" />
                Case Association (Optional)
              </span>
              <span className="text-[11px] font-mono text-[var(--text-muted)]">
                Preserve evidence master copies & chain of custody
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 font-mono">
              <button
                type="button"
                onClick={() => setCaseMode('session')}
                className={`p-3 rounded-lg text-left border text-xs transition-all cursor-pointer ${
                  caseMode === 'session'
                    ? 'border-[var(--accent-cobalt)] bg-[var(--accent-subtle)] text-[var(--accent-cobalt)] font-semibold'
                    : 'border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-secondary)] hover:border-[var(--border-strong)]'
                }`}
              >
                <div className="font-bold text-[var(--text-primary)]">Transient Session</div>
                <div className="text-[10px] text-[var(--text-muted)] mt-0.5">Quick ad-hoc triage without vault storage</div>
              </button>

              <button
                type="button"
                onClick={() => setCaseMode('existing')}
                className={`p-3 rounded-lg text-left border text-xs transition-all cursor-pointer ${
                  caseMode === 'existing'
                    ? 'border-[var(--accent-cobalt)] bg-[var(--accent-subtle)] text-[var(--accent-cobalt)] font-semibold'
                    : 'border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-secondary)] hover:border-[var(--border-strong)]'
                }`}
              >
                <div className="font-bold text-[var(--text-primary)]">Attach to Case</div>
                <div className="text-[10px] text-[var(--text-muted)] mt-0.5">Link evidence to an existing open case</div>
              </button>

              <button
                type="button"
                onClick={() => setCaseMode('new')}
                className={`p-3 rounded-lg text-left border text-xs transition-all cursor-pointer ${
                  caseMode === 'new'
                    ? 'border-[var(--accent-cobalt)] bg-[var(--accent-subtle)] text-[var(--accent-cobalt)] font-semibold'
                    : 'border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-secondary)] hover:border-[var(--border-strong)]'
                }`}
              >
                <div className="font-bold text-[var(--text-primary)]">+ Create New Case</div>
                <div className="text-[10px] text-[var(--text-muted)] mt-0.5">Initialize a new case ID with this upload</div>
              </button>
            </div>

            {/* Case Mode Inputs */}
            {caseMode === 'existing' && (
              <div className="pt-2 font-mono">
                <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">
                  Select Open Investigation:
                </label>
                {openCases.length === 0 ? (
                  <div className="text-xs text-[var(--text-muted)] p-2.5 bg-[var(--bg-subtle)] rounded-lg border border-[var(--border-hairline)]">
                    No open cases found. Please select &quot;+ Create New Case&quot; to establish an investigation.
                  </div>
                ) : (
                  <select
                    value={selectedCaseId}
                    onChange={(e) => setSelectedCaseId(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] border border-[var(--border-hairline)] rounded-lg focus:outline-none focus:border-[var(--accent-cobalt)]"
                  >
                    {openCases.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.id} — {c.title} ({c.investigator || 'Unassigned'})
                      </option>
                    ))}
                  </select>
                )}
              </div>
            )}

            {caseMode === 'new' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 font-mono">
                <div>
                  <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">
                    Case Title:
                  </label>
                  <input
                    type="text"
                    placeholder="e.g., Incident 2026-Q4 Contract Tampering"
                    value={newCaseTitle}
                    onChange={(e) => setNewCaseTitle(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] border border-[var(--border-hairline)] rounded-lg focus:outline-none focus:border-[var(--accent-cobalt)]"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">
                    Lead Investigator:
                  </label>
                  <input
                    type="text"
                    placeholder="e.g., Detective Sharma"
                    value={newCaseInvestigator}
                    onChange={(e) => setNewCaseInvestigator(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] border border-[var(--border-hairline)] rounded-lg focus:outline-none focus:border-[var(--accent-cobalt)]"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Submission / Pipeline Progress Execution Card */}
          <div className="pt-2">
            {isSubmitting ? (
              <div className="p-5 rounded-xl border border-[var(--border-strong)] bg-[var(--bg-surface)] space-y-3 lab-card">
                <div className="flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center gap-2 text-[var(--accent-cobalt)] font-semibold">
                    <Cpu className="w-4 h-4 animate-spin" />
                    <span>{analysisStage || 'Executing multi-engine inspection...'}</span>
                  </div>
                  <span className="font-bold text-[var(--text-primary)]">
                    {uploadProgress !== null ? `${uploadProgress}%` : 'Processing'}
                  </span>
                </div>

                <div className="h-2 w-full rounded-full bg-[var(--bg-subtle)] border border-[var(--border-hairline)] overflow-hidden">
                  <div
                    className="h-full bg-[var(--accent-cobalt)] transition-all duration-300 ease-out"
                    style={{ width: `${uploadProgress || 20}%` }}
                  />
                </div>

                <div className="flex items-center justify-between text-[11px] font-mono text-[var(--text-muted)]">
                  <span>Local sandboxed streaming</span>
                  <span>Zero cloud telemetry</span>
                </div>
              </div>
            ) : (
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] lab-card">
                <div className="text-xs font-mono text-[var(--text-muted)]">
                  Total Payload: <strong className="text-[var(--text-primary)]">{totalCount}</strong> files ({formatBytes(totalBytes)})
                </div>

                <div className="flex items-center gap-3">
                  <Button
                    variant="outline"
                    size="md"
                    onClick={clearQueue}
                  >
                    Clear Queue
                  </Button>
                  <Button
                    variant="accent"
                    size="md"
                    icon={FileSearch}
                    onClick={handleStartAnalysis}
                  >
                    Execute Forensic Inspection
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Forensic Privacy Disclaimer */}
      <div className="p-4 rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-subtle)] flex items-start gap-3 text-xs text-[var(--text-muted)]">
        <Lock className="w-4 h-4 text-[var(--status-low)] shrink-0 mt-0.5" />
        <p className="leading-relaxed font-mono text-[11px]">
          <strong className="text-[var(--text-primary)]">Evidentiary Integrity Guarantee:</strong> Uploaded evidence is streamed into local memory for analysis and is never transmitted to external cloud services or third-party AI APIs. Original evidence hashes (SHA-256) are calculated before extraction.
        </p>
      </div>
    </div>
  );
}
