/**
 * PRAMAANX - Forensic Inspection Report Controller
 * Matches PRAMAANX design reference system:
 * - Slim sticky header with view switch (Simple / Technical) & primary "Analyze another file" action
 * - Unified ForensicResults presentation for Single-File and Individual Batch-File reports
 * - Complete Batch Triage: 6-metric summary ribbon, clean file result cards, "Open Full Report"
 * - Instant Prev/Next and Dropdown switching between batch specimens
 * - Preserves complete forensic depth across all laboratory tabs
 * - Robust persistence across browser refresh and back/forward navigation
 */

import { useState, useMemo, useEffect, useCallback } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import ResultsHeader from '../components/results/ResultsHeader';
import ForensicResults from '../components/results/ForensicResults';
import BatchOverview from '../components/results/BatchOverview';
import BatchNavHeader from '../components/results/BatchNavHeader';
import MetadataTab from '../components/results/MetadataTab';
import Modal from '../components/common/Modal';
import Button from '../components/common/Button';
import {
  FileSearch,
  FolderArchive,
  ShieldCheck,
  Info,
  AlertTriangle,
  ArrowLeft,
} from 'lucide-react';
import { ROUTES } from '../utils/constants';
import { buildMetadataReport } from '../utils/metadataHelpers';

export default function AnalysisResults() {
  const location = useLocation();
  const navigate = useNavigate();
  const { batchId: routeBatchId, fileId: routeFileId } = useParams();

  // 1. Resolve State Data from React Router location or Session Storage
  const stateData = useMemo(() => {
    // A. Check location state
    if (location.state?.result) {
      return location.state;
    }
    // B. Check batch session storage if batchId in route or latest batch cached
    const targetBatchId =
      routeBatchId ||
      (typeof window !== 'undefined' ? sessionStorage.getItem('pramaanx_latest_batch') : null);
    if (targetBatchId && typeof window !== 'undefined') {
      try {
        const cached = sessionStorage.getItem(`pramaanx_batch_${targetBatchId}`);
        if (cached) {
          return JSON.parse(cached);
        }
      } catch {
        // Ignore JSON error
      }
    }
    // C. Check single analysis session storage
    if (typeof window !== 'undefined') {
      try {
        const singleCached = sessionStorage.getItem('pramaanx_latest_single');
        if (singleCached) {
          return JSON.parse(singleCached);
        }
      } catch {
        // Ignore JSON error
      }
      try {
        const archiveCached = sessionStorage.getItem('pramaanx_latest_archive');
        if (archiveCached) {
          return JSON.parse(archiveCached);
        }
      } catch {
        // Ignore JSON error
      }
    }
    return null;
  }, [location.state, routeBatchId]);

  // Sync incoming location state to external sessionStorage
  useEffect(() => {
    if (location.state?.result) {
      const incoming = location.state;
      if (incoming.type === 'batch') {
        const bId = incoming.batchId || routeBatchId || `batch_${Date.now()}`;
        try {
          sessionStorage.setItem(
            `pramaanx_batch_${bId}`,
            JSON.stringify({
              ...incoming,
              batchId: bId,
            })
          );
          sessionStorage.setItem('pramaanx_latest_batch', bId);
        } catch {
          // Ignore quota errors
        }
      } else if (incoming.type === 'single') {
        try {
          sessionStorage.setItem('pramaanx_latest_single', JSON.stringify(incoming));
        } catch {
          // Ignore quota errors
        }
      } else if (incoming.type === 'archive') {
        try {
          sessionStorage.setItem('pramaanx_latest_archive', JSON.stringify(incoming));
        } catch {
          // Ignore quota errors
        }
      }
    }
  }, [location.state, routeBatchId]);

  // 2. View Mode (Simple vs Technical), persisted in localStorage
  const [viewMode, setViewMode] = useState(() => {
    try {
      return localStorage.getItem('pramaanx-results-view-mode') || 'simple';
    } catch {
      return 'simple';
    }
  });

  const handleToggleViewMode = (mode) => {
    setViewMode(mode);
    try {
      localStorage.setItem('pramaanx-results-view-mode', mode);
    } catch {
      // Ignore storage errors
    }
  };

  const [previewImage, setPreviewImage] = useState(null);

  // 3. Inspect Payload and Determine Analysis Scope
  const result = stateData?.result;
  const analysisType = stateData?.type || (result?.summary ? 'batch' : result?.archive_safety ? 'archive' : 'single');

  const isBatch = analysisType === 'batch' && !!result?.summary && !!result?.results;
  const isArchive = analysisType === 'archive' && !!result?.archive_safety;
  const isSingle = !isBatch && !isArchive && !!result?.file && !!result?.analysis;

  // 4. Batch Sub-route Resolution: Active File Index
  const activeFileIndex = useMemo(() => {
    if (!isBatch || !routeFileId) return null;
    const numericIndex = Number(routeFileId);
    if (!isNaN(numericIndex) && numericIndex >= 0 && numericIndex < (result?.results?.length || 0)) {
      return numericIndex;
    }
    // Support fileId matched by filename
    const foundIdx = (result?.results || []).findIndex(
      (r) => r.filename === routeFileId || encodeURIComponent(r.filename) === routeFileId
    );
    return foundIdx !== -1 ? foundIdx : null;
  }, [isBatch, routeFileId, result]);

  // Active Batch Item Details
  const activeBatchItem = useMemo(() => {
    if (!isBatch || activeFileIndex === null) return null;
    return result?.results?.[activeFileIndex] || null;
  }, [isBatch, activeFileIndex, result]);

  // Batch Navigation Handlers
  const currentBatchId = stateData?.batchId || routeBatchId || 'current';

  const handleOpenBatchReport = useCallback(
    (fileIdx) => {
      navigate(`/analysis/results/batch/${currentBatchId}/${fileIdx}`, {
        state: stateData,
      });
    },
    [navigate, currentBatchId, stateData]
  );

  const handleBackToBatch = useCallback(() => {
    navigate(`/analysis/results/batch/${currentBatchId}`, {
      state: stateData,
    });
  }, [navigate, currentBatchId, stateData]);

  const handleSelectBatchIndex = useCallback(
    (newIdx) => {
      navigate(`/analysis/results/batch/${currentBatchId}/${newIdx}`, {
        state: stateData,
      });
    },
    [navigate, currentBatchId, stateData]
  );

  const handleDownloadReport = useCallback(() => {
    if (stateData?.caseId) {
      navigate(ROUTES.REPORTS, {
        state: { caseId: stateData.caseId },
      });
    } else {
      navigate(ROUTES.REPORTS);
    }
  }, [navigate, stateData]);

  // Single File Details
  const singleFileInfo = isSingle ? result?.file : null;
  const singleAnalysis = isSingle ? result?.analysis : null;
  const singleFilePreview = stateData?.filePreview || null;

  // Archive Metadata Report
  const archiveMetadataReport = useMemo(() => {
    if (!isArchive || !result?.archive_metadata) return null;
    return buildMetadataReport(
      'zip',
      'application/zip',
      result.archive_metadata,
      { detected_type: 'zip' }
    );
  }, [isArchive, result]);

  // Fallback if accessed without analysis data
  if (!result) {
    return (
      <div className="max-w-xl mx-auto py-20 px-4 text-center space-y-6">
        <div className="w-16 h-16 rounded-2xl bg-[var(--soft)] border border-[var(--line)] flex items-center justify-center mx-auto text-[var(--brand)] shadow-xs">
          <FileSearch className="w-8 h-8" />
        </div>
        <div className="space-y-2">
          <h2 className="text-2xl font-extrabold text-[var(--ink)] tracking-tight">
            No active inspection record found
          </h2>
          <p className="text-sm text-[var(--mute)] max-w-md mx-auto leading-relaxed">
            You may have refreshed the page or navigated directly. Please select a document or image to begin forensic inspection.
          </p>
        </div>
        <div>
          <Button
            variant="primary"
            size="md"
            icon={FileSearch}
            onClick={() => navigate(ROUTES.ANALYZE)}
          >
            Go to evidence intake
          </Button>
        </div>
      </div>
    );
  }

  // Active Specimen Name & Type for Header
  let headerFileName = 'Inspection Report';
  let headerDetectedType = null;

  if (isSingle) {
    headerFileName = singleFileInfo?.filename || 'Document Specimen';
    headerDetectedType = singleFileInfo?.detected_type || null;
  } else if (isArchive) {
    headerFileName = result.archive_filename || 'Archive Inspection';
    headerDetectedType = 'ZIP';
  } else if (isBatch) {
    if (activeBatchItem) {
      headerFileName = activeBatchItem.filename;
      headerDetectedType = activeBatchItem.file?.detected_type || 'SPECIMEN';
    } else {
      headerFileName = 'Batch Forensic Triage';
      headerDetectedType = 'BATCH';
    }
  }

  return (
    <div className="space-y-8 pb-20">
      {/* 1. Slim Sticky Results Header */}
      <ResultsHeader
        fileName={headerFileName}
        detectedType={headerDetectedType}
        viewMode={viewMode}
        onToggleViewMode={handleToggleViewMode}
      />

      <div className="max-w-[1160px] mx-auto px-4 sm:px-6 space-y-8">
        {/* Case Preservation Banner (if attached to an investigation) */}
        {stateData?.caseId && (
          <div className="p-4 rounded-[22px] bg-[var(--card)] border border-[var(--line)] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs shadow-xs">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-[var(--soft)] flex items-center justify-center text-[var(--brand)]">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <span className="text-[var(--ink)]">
                Evidence preserved in Case <strong className="font-mono text-[var(--brand)]">{stateData.caseId}</strong> with immutable SHA-256 custody baseline.
              </span>
            </div>
            <Button
              variant="outline"
              size="sm"
              icon={FolderArchive}
              onClick={() => navigate(ROUTES.INVESTIGATIONS)}
            >
              Open case dossier
            </Button>
          </div>
        )}

        {/* ================================================================== */}
        {/* SINGLE FILE FORENSIC RESULTS                                       */}
        {/* ================================================================== */}
        {isSingle && (
          <ForensicResults
            fileInfo={singleFileInfo}
            analysis={singleAnalysis}
            filePreview={singleFilePreview}
            viewMode={viewMode}
            onOpenZoom={(imgObj) => setPreviewImage(imgObj)}
            onDownloadReport={handleDownloadReport}
          />
        )}

        {/* ================================================================== */}
        {/* BATCH ANALYSIS: BATCH OVERVIEW vs INDIVIDUAL FILE REPORT           */}
        {/* ================================================================== */}
        {isBatch && (
          <div>
            {/* Case A: Specific Batch File Full Report View */}
            {activeBatchItem ? (
              activeBatchItem.status === 'success' && activeBatchItem.analysis ? (
                <div className="space-y-6">
                  {/* Batch Navigation Sub-Bar */}
                  <BatchNavHeader
                    currentIndex={activeFileIndex}
                    totalFiles={result.results.length}
                    currentFileName={activeBatchItem.filename}
                    currentRiskScore={activeBatchItem.analysis.risk_score}
                    batchResults={result.results}
                    onSelectIndex={handleSelectBatchIndex}
                    onBackToBatch={handleBackToBatch}
                  />

                  {/* Complete Forensic Results — Identical to Single-File */}
                  <ForensicResults
                    fileInfo={activeBatchItem.file}
                    analysis={activeBatchItem.analysis}
                    filePreview={stateData?.filePreviews?.[activeBatchItem.filename] || null}
                    viewMode={viewMode}
                    onOpenZoom={(imgObj) => setPreviewImage(imgObj)}
                    onDownloadReport={handleDownloadReport}
                  />
                </div>
              ) : (
                /* Failed Batch Item Detail View */
                <div className="space-y-6">
                  <div className="p-4 rounded-[22px] bg-[var(--card)] border border-[var(--line)] shadow-xs flex items-center justify-between">
                    <Button
                      variant="outline"
                      size="sm"
                      icon={ArrowLeft}
                      onClick={handleBackToBatch}
                    >
                      Back to Batch Overview
                    </Button>
                    <span className="text-xs font-bold text-[var(--bad)]">
                      Specimen Examination Failed
                    </span>
                  </div>

                  <div className="p-8 rounded-[26px] border border-[var(--line)] bg-[var(--card)] text-center space-y-4 shadow-xs max-w-xl mx-auto">
                    <div className="w-14 h-14 rounded-2xl bg-[var(--soft)] text-[var(--bad)] flex items-center justify-center mx-auto">
                      <AlertTriangle className="w-7 h-7" />
                    </div>
                    <div className="space-y-1">
                      <h3 className="font-extrabold text-lg text-[var(--ink)] tracking-tight">
                        {activeBatchItem.filename}
                      </h3>
                      <p className="text-xs font-mono text-[var(--bad)]">
                        {activeBatchItem.error?.code || 'PROCESSING_FAILED'}
                      </p>
                    </div>
                    <p className="text-sm text-[var(--mute)] leading-relaxed">
                      {activeBatchItem.error?.message ||
                        'This file could not be analyzed. It may be corrupt, password-protected, or of an unsupported format.'}
                    </p>
                    <div className="pt-2">
                      <Button
                        variant="primary"
                        size="md"
                        icon={ArrowLeft}
                        onClick={handleBackToBatch}
                      >
                        Return to batch overview
                      </Button>
                    </div>
                  </div>
                </div>
              )
            ) : (
              /* Case B: Batch-Level Overview Ribbon & Diagnostic Cards */
              <BatchOverview
                summary={result.summary}
                results={result.results}
                onOpenReport={handleOpenBatchReport}
              />
            )}
          </div>
        )}

        {/* ================================================================== */}
        {/* ARCHIVE ANALYSIS VIEW                                              */}
        {/* ================================================================== */}
        {isArchive && (
          <div className="space-y-6 text-xs">
            {/* Archive Pre-Extraction Safety Card */}
            <div className="p-6 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-5 shadow-xs">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[var(--line)]">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-2xl bg-[var(--soft)] border border-[var(--line)] flex items-center justify-center text-[var(--brand)]">
                    <FolderArchive className="w-5 h-5" />
                  </div>
                  <div>
                    <h2 className="text-base font-bold text-[var(--ink)]">
                      {result.archive_filename}
                    </h2>
                    <p className="text-xs text-[var(--mute)]">
                      Pre-extraction sandbox validation & structure integrity
                    </p>
                  </div>
                </div>
                <span
                  className={`text-xs font-bold uppercase tracking-wider px-3 py-1 rounded-full border ${
                    result.archive_safety.is_safe
                      ? 'bg-[var(--soft)] text-[var(--ok)] border-[var(--ok)]'
                      : 'bg-[var(--soft)] text-[var(--bad)] border-[var(--bad)]'
                  }`}
                >
                  {result.archive_safety.is_safe ? 'Archive Safe' : 'Safety Violation'}
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="p-4 rounded-2xl bg-[var(--soft)]/50 border border-[var(--line)]">
                  <span className="text-[var(--mute)] block text-xs">Total archive entries</span>
                  <span className="font-bold text-[var(--ink)] text-base block mt-0.5">
                    {result.archive_safety.total_entries_found}
                  </span>
                </div>
                <div className="p-4 rounded-2xl bg-[var(--soft)]/50 border border-[var(--line)]">
                  <span className="text-[var(--mute)] block text-xs">Safe screened entries</span>
                  <span className="font-bold text-[var(--ink)] text-base block mt-0.5">
                    {result.archive_safety.safe_entries_count}
                  </span>
                </div>
                <div className="p-4 rounded-2xl bg-[var(--soft)]/50 border border-[var(--line)] col-span-2 sm:col-span-1">
                  <span className="text-[var(--mute)] block text-xs">Zip slip & bomb protection</span>
                  <span className="font-bold text-[var(--ok)] block mt-0.5">
                    Passed Pre-Extraction
                  </span>
                </div>
              </div>
            </div>

            {/* Archive Metadata Section */}
            {archiveMetadataReport && (
              <MetadataTab metadataReport={archiveMetadataReport} viewMode={viewMode} />
            )}
          </div>
        )}

        {/* 5. Compact Evidentiary Footnote */}
        <div className="pt-6 border-t border-[var(--line)] flex items-start gap-2.5 text-xs text-[var(--mute)]">
          <Info className="w-4 h-4 text-[var(--brand)] shrink-0 mt-0.5" />
          <p className="leading-relaxed text-xs">
            <strong className="text-[var(--ink)]">Evidentiary disclaimer:</strong> All assessments generated by PRAMAANX represent automated forensic triage indicators and are not a substitute for formal courtroom certified testimony. File custody hashes (SHA-256) are calculated prior to examination.
          </p>
        </div>
      </div>

      {/* Full-Screen Zoom Modal */}
      {previewImage && (
        <Modal
          isOpen={Boolean(previewImage)}
          onClose={() => setPreviewImage(null)}
          title={previewImage.title || 'Visual Evidence Zoom'}
          subtitle={previewImage.caption}
          maxWidth="max-w-4xl"
        >
          <div className="space-y-4">
            <div className="relative rounded-2xl border border-[var(--line)] bg-black/95 overflow-hidden max-h-[75vh] flex items-center justify-center p-2">
              <img
                src={previewImage.src}
                alt={previewImage.title}
                className="max-h-[70vh] w-auto object-contain select-none"
              />
            </div>
            {previewImage.caption && (
              <p className="text-xs text-[var(--mute)] bg-[var(--soft)] p-3 rounded-xl border border-[var(--line)]">
                {previewImage.caption}
              </p>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}
