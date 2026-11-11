/**
 * PRAMAANX - Shared Forensic Results Presentation Component
 * Used identically for Single-File analysis and Batch-File individual reports.
 * Preserves complete forensic depth across all 5 laboratory inspection tabs.
 */

import { useState, useMemo } from 'react';
import HeroVerdict from './HeroVerdict';
import OverviewTab from './OverviewTab';
import VisualEvidenceTab from './VisualEvidenceTab';
import MetadataTab from './MetadataTab';
import TechnicalTab from './TechnicalTab';
import PipelineTab from './PipelineTab';
import { getAiAssessment, getFileSpecificChecklist, getPlainEnglishVerdict } from '../../utils/explainabilityHelpers';
import { buildMetadataReport } from '../../utils/metadataHelpers';
import { resolveMediaUrl } from '../../services/api';

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'visual', label: 'Visual Evidence' },
  { id: 'metadata', label: 'Metadata' },
  { id: 'technical', label: 'Technical Details' },
  { id: 'pipeline', label: 'Pipeline' },
];

export default function ForensicResults({
  fileInfo,
  analysis,
  filePreview = null,
  viewMode = 'simple',
  onOpenZoom,
  onDownloadReport,
  topBanner = null,
}) {
  const [activeTab, setActiveTab] = useState('overview');

  const rawFindings = useMemo(() => analysis?.findings || [], [analysis]);

  // Derived Plain-English Verdict
  const verdict = useMemo(() => {
    if (!analysis) return null;
    return getPlainEnglishVerdict(
      analysis.risk_score,
      analysis.risk_category,
      rawFindings,
      fileInfo?.detected_type || fileInfo?.type,
      analysis
    );
  }, [analysis, rawFindings, fileInfo]);

  // File-specific Examination Checklist
  const examinationChecklist = useMemo(() => {
    if (!fileInfo) return [];
    return getFileSpecificChecklist(
      fileInfo.detected_type || fileInfo.type,
      fileInfo.detected_mime,
      rawFindings
    );
  }, [fileInfo, rawFindings]);

  // AI Screening Assessment
  const aiAssessment = useMemo(() => {
    if (!analysis) return null;
    return getAiAssessment(
      rawFindings,
      analysis,
      fileInfo?.detected_type || fileInfo?.type
    );
  }, [analysis, rawFindings, fileInfo]);

  // Structured Metadata Report
  const metadataReport = useMemo(() => {
    if (!fileInfo) return null;
    return buildMetadataReport(
      fileInfo.detected_type || fileInfo.type,
      fileInfo.detected_mime,
      analysis?.metadata || {},
      fileInfo
    );
  }, [fileInfo, analysis]);

  if (!fileInfo || !analysis) {
    return null;
  }

  // Unified original specimen URL (prefers persistent backend endpoint, falls back to memory blob)
  const resolvedOriginalUrl = resolveMediaUrl(analysis?.visual_evidence?.original_url) || filePreview || null;
  const resolvedGradcamUrl = resolveMediaUrl(analysis?.visual_evidence?.gradcam_url);
  const resolvedElaUrl = resolveMediaUrl(analysis?.visual_evidence?.ela_url);

  return (
    <div className="space-y-8">
      {/* Optional Top Banner (Batch Switcher or Case Custody) */}
      {topBanner}

      {/* Hero Verdict (Visual Overlay, Risk Gauge, Key Signals Strip) */}
      <HeroVerdict
        fileInfo={fileInfo}
        analysis={analysis}
        verdict={verdict}
        aiAssessment={aiAssessment}
        filePreview={resolvedOriginalUrl}
        onSelectTab={(tabId) => setActiveTab(tabId)}
        onOpenZoom={onOpenZoom}
        onDownloadReport={onDownloadReport}
      />

      {/* Tab Navigation Bar */}
      <div className="border-b border-[var(--line)] pt-3">
        <nav
          role="tablist"
          aria-label="Inspection report sections"
          className="flex items-center gap-2 overflow-x-auto pb-px scrollbar-none"
        >
          {TABS.map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                role="tab"
                aria-selected={isActive}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2.5 rounded-t-xl text-sm font-bold transition-all duration-200 cursor-pointer shrink-0 border-b-2 ${
                  isActive
                    ? 'border-[var(--brand)] text-[var(--brand)] bg-[var(--soft)]/50'
                    : 'border-transparent text-[var(--mute)] hover:text-[var(--ink)] hover:border-[var(--line)]'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Active Tab Content Pane */}
      <div className="pt-2 min-h-[350px]">
        {activeTab === 'overview' && (
          <OverviewTab
            findings={rawFindings}
            riskScore={analysis.risk_score}
            fileType={fileInfo?.detected_type}
            onNavigateTab={(tabId) => setActiveTab(tabId)}
          />
        )}

        {activeTab === 'visual' && (
          <VisualEvidenceTab
            originalUrl={resolvedOriginalUrl}
            gradcamUrl={resolvedGradcamUrl}
            elaUrl={resolvedElaUrl}
            elaStats={
              analysis.findings?.find((f) => (f.title || '').includes('ELA'))?.evidence ||
              analysis.metadata?.ela_stats
            }
            isRecompressed={Boolean(
              analysis.jpeg_structure?.likely_messaging_app_recompression ||
                (analysis.jpeg_structure?.estimated_quality &&
                  analysis.jpeg_structure.estimated_quality < 80)
            )}
            viewMode={viewMode}
            onOpenZoom={onOpenZoom}
          />
        )}

        {activeTab === 'metadata' && (
          <MetadataTab
            metadataReport={metadataReport}
            jpegStructure={analysis.jpeg_structure}
            viewMode={viewMode}
          />
        )}

        {activeTab === 'technical' && (
          <TechnicalTab
            fileInfo={fileInfo}
            analysis={analysis}
            examinationChecklist={examinationChecklist}
            findings={rawFindings}
          />
        )}

        {activeTab === 'pipeline' && (
          <PipelineTab
            fileInfo={fileInfo}
            analysis={analysis}
          />
        )}
      </div>
    </div>
  );
}

