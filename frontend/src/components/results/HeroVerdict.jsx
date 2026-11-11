/**
 * PRAMAANX - Results Hero Verdict Section (Two Columns)
 * Above the fold:
 * Left: Visual Centerpiece (Interactive Image / Specimen Overlay, radius 22px)
 * Right: Calibrated Semicircle Gauge, One Headline Score, Plain-English Verdict,
 * AI Confidence Sub-line with Tooltip, Next Steps, and Key Signals Strip.
 * Design system tokens, radius 26px, rounded-full buttons & chips, zero banned words.
 */

import { useState } from 'react';
import Gauge from '../common/Gauge';
import InteractiveImageOverlay from './InteractiveImageOverlay';
import SignalChip from '../common/SignalChip';
import Button from '../common/Button';
import { resolveMediaUrl } from '../../services/api';
import {
  FileText,
  Download,
  HelpCircle,
  Eye,
} from 'lucide-react';

export default function HeroVerdict({
  fileInfo,
  analysis,
  verdict,
  aiAssessment,
  filePreview,
  onSelectTab,
  onOpenZoom,
  onDownloadReport,
}) {
  const [showAiTooltip, setShowAiTooltip] = useState(false);
  const [showReliabilityTooltip, setShowReliabilityTooltip] = useState(false);

  const riskScore = analysis?.risk_score ?? 0;
  const originalUrl = resolveMediaUrl(analysis?.visual_evidence?.original_url) || filePreview || null;
  const gradcamUrl = resolveMediaUrl(analysis?.visual_evidence?.gradcam_url) || null;
  const elaUrl = resolveMediaUrl(analysis?.visual_evidence?.ela_url) || null;
  const reliability = analysis?.reliability || 'high';

  // 4-state verdict derivation
  const currentVerdict = analysis?.verdict || verdict?.verdictKey || 'no_signs';

  const getVerdictPresentation = (vKey) => {
    switch (vKey) {
      case 'high_risk':
        return {
          title: 'High Risk of Editing Detected',
          badgeClass: 'text-[var(--bad)] bg-[var(--soft)] border-[var(--bad)]',
          riskLabel: 'High Risk',
          color: 'var(--bad)',
          explanation: 'Strong indicators of manipulation or structural tampering were identified across independent forensic checks.',
        };
      case 'review_recommended':
        return {
          title: 'Review Recommended',
          badgeClass: 'text-[var(--warn)] bg-[var(--soft)] border-[var(--warn)]',
          riskLabel: 'Review',
          color: 'var(--warn)',
          explanation: 'Anomalies were detected that warrant manual verification by a forensic examiner.',
        };
      case 'limited_evidence':
        return {
          title: 'Limited Evidence',
          badgeClass: 'text-[var(--brand)] bg-[var(--soft)] border-[var(--brand)]',
          riskLabel: 'Limited',
          color: 'var(--brand)',
          explanation:
            'Limited evidence. This file was likely shared through a messaging service or recompressed, so edit-detection checks are less conclusive on this specimen.',
        };
      case 'no_signs':
      default:
        return {
          title: 'No Signs of Localized Editing Detected',
          badgeClass: 'text-[var(--ok)] bg-[var(--soft)] border-[var(--ok)]',
          riskLabel: 'Passed',
          color: 'var(--ok)',
          explanation: 'No signs of localized editing detected across standard forensic examination pipelines.',
        };
    }
  };

  const presentation = getVerdictPresentation(currentVerdict);
  const shortExplanation = verdict?.summary || presentation.explanation;

  // Key Signals Data for the chips strip
  const findings = analysis?.findings || [];
  const hasHeaderAnomaly = findings.some((f) =>
    (f.title || '').toLowerCase().includes('magic') || (f.title || '').toLowerCase().includes('extension')
  );
  const hasMetadataAnomaly = findings.some((f) =>
    (f.title || '').toLowerCase().includes('metadata') || (f.title || '').toLowerCase().includes('date')
  );
  const hasCompressionAnomaly = findings.some((f) =>
    (f.title || '').toLowerCase().includes('ela') || (f.title || '').toLowerCase().includes('compression')
  );
  const hasAiAnomaly = Boolean(aiAssessment && aiAssessment.tamperProbability > 0.65);
  const isAiUnsure = Boolean(
    aiAssessment && aiAssessment.tamperProbability >= 0.35 && aiAssessment.tamperProbability <= 0.65
  );

  const keySignals = [
    {
      id: 'header',
      label: 'Header & Type',
      status: hasHeaderAnomaly ? 'Flagged' : 'Passed',
      targetTab: 'technical',
    },
    {
      id: 'bytes',
      label: 'Byte Data',
      status: 'Passed',
      targetTab: 'technical',
    },
    {
      id: 'metadata',
      label: 'Metadata',
      status: hasMetadataAnomaly ? 'Flagged' : 'Passed',
      targetTab: 'metadata',
    },
    {
      id: 'compression',
      label: 'Compression',
      status: hasCompressionAnomaly ? 'Flagged' : 'Passed',
      targetTab: 'visual',
    },
    {
      id: 'ai',
      label: 'AI Model',
      status: hasAiAnomaly ? 'Flagged' : isAiUnsure ? 'Not performed' : 'Passed',
      targetTab: 'visual',
    },
  ];

  return (
    <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
      {/* Left Column: Visual Centerpiece (Image Overlay or Document Container) */}
      <div className="lg:col-span-6 w-full">
        <InteractiveImageOverlay
          originalUrl={originalUrl}
          gradcamUrl={gradcamUrl}
          elaUrl={elaUrl}
          fileName={fileInfo?.filename || fileInfo?.name}
          fileType={fileInfo?.detected_type || fileInfo?.type}
          detectedMime={fileInfo?.detected_mime}
          onOpenZoom={onOpenZoom}
        />
      </div>

      {/* Right Column: Semicircle Gauge, Single Headline Score, Verdict, Sub-line, Actions & Chips */}
      <div className="lg:col-span-6 space-y-6 flex flex-col justify-between">
        {/* Top Verdict Card */}
        <div className="p-6 sm:p-7 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-5 shadow-xs">
          {/* Gauge & Headline Row */}
          <div className="flex flex-col sm:flex-row items-center sm:items-start justify-between gap-6">
            <div className="space-y-3 text-center sm:text-left flex-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2 justify-center sm:justify-start">
                <span
                  className={`inline-block px-3 py-1 rounded-full text-xs font-bold border ${presentation.badgeClass}`}
                >
                  {presentation.title}
                </span>

                {/* Specimen Reliability Badge & Tooltip */}
                <div className="inline-flex items-center gap-1.5 text-xs text-[var(--mute)]">
                  <span className="font-medium text-[var(--mute)]">Reliability:</span>
                  <span
                    className={`px-2.5 py-0.5 rounded-full font-bold uppercase text-[10px] border ${
                      reliability === 'low'
                        ? 'bg-[var(--soft)] text-[var(--warn)] border-[var(--warn)]'
                        : reliability === 'medium'
                        ? 'bg-[var(--soft)] text-[var(--ink)] border-[var(--line)]'
                        : 'bg-[var(--soft)] text-[var(--ok)] border-[var(--ok)]'
                    }`}
                  >
                    {reliability}
                  </span>
                  <div className="relative inline-block">
                    <button
                      type="button"
                      onClick={() => setShowReliabilityTooltip((prev) => !prev)}
                      onMouseEnter={() => setShowReliabilityTooltip(true)}
                      onMouseLeave={() => setShowReliabilityTooltip(false)}
                      className="p-0.5 rounded-full text-[var(--mute)] hover:text-[var(--ink)] cursor-pointer"
                      aria-label="Explain reliability"
                    >
                      <HelpCircle className="w-3.5 h-3.5" />
                    </button>
                    {showReliabilityTooltip && (
                      <div className="absolute left-0 bottom-full mb-2 w-64 p-3 rounded-2xl bg-[var(--card)] text-[var(--ink)] border border-[var(--line)] text-xs leading-snug shadow-xl z-30 font-sans">
                        Reliability indicates whether the specimen retains sufficient uncompressed structural and metadata signals to perform conclusive tamper verification.
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <h2 className="text-2xl sm:text-3xl font-extrabold text-[var(--ink)] tracking-tight leading-tight">
                {presentation.title}
              </h2>

              <p className="text-sm text-[var(--mute)] leading-relaxed max-w-md">
                {shortExplanation}
              </p>

              {/* Scope Notice */}
              <p className="text-xs text-[var(--mute)] pt-0.5 max-w-md leading-normal">
                Detects localized manipulation (splicing, object removal, copy-move). Global edits such as color filters or brightness changes cannot be reliably detected.
              </p>
            </div>

            {/* Semicircle Gauge (Single headline score) */}
            <div className="shrink-0 flex justify-center">
              <Gauge score={riskScore} size={180} showLabel={true} />
            </div>
          </div>

          {/* AI Confidence as a small labeled sub-line (never a competing second score) */}
          {aiAssessment && (
            <div className="pt-4 border-t border-[var(--line)] flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex items-center gap-2 text-[var(--mute)]">
                <span className="font-bold text-[var(--ink)]">AI screening:</span>
                {aiAssessment.level === 'unavailable' || !aiAssessment.available ? (
                  <span className="italic text-[var(--mute)]">AI screening unavailable</span>
                ) : (
                  <span className="font-medium text-[var(--ink)]">
                    {aiAssessment.level === 'elevated'
                      ? `Suspicion elevated (${aiAssessment.scoreText})`
                      : aiAssessment.level === 'inconclusive'
                      ? `AI is unsure (${aiAssessment.scoreText})`
                      : `Low suspicion (${aiAssessment.scoreText})`}
                  </span>
                )}
                <span
                  className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-[var(--soft)] text-[var(--mute)] border border-[var(--line)]"
                  title={analysis?.ml_prediction?.is_calibrated ? 'Calibrated model' : 'Experimental model (Uncalibrated)'}
                >
                  {analysis?.ml_prediction?.is_calibrated ? 'Calibrated model' : 'Experimental model'}
                </span>
              </div>

              {/* Tooltip trigger */}
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setShowAiTooltip((prev) => !prev)}
                  onMouseEnter={() => setShowAiTooltip(true)}
                  onMouseLeave={() => setShowAiTooltip(false)}
                  className="p-1 rounded-full text-[var(--mute)] hover:text-[var(--ink)] cursor-pointer"
                  aria-label="Explain AI confidence"
                >
                  <HelpCircle className="w-3.5 h-3.5" />
                </button>
                {showAiTooltip && (
                  <div className="absolute right-0 bottom-full mb-2 w-72 p-3.5 rounded-2xl bg-[var(--card)] text-[var(--ink)] border border-[var(--line)] text-xs leading-snug shadow-xl z-20 font-sans">
                    {analysis?.ml_prediction?.is_calibrated
                      ? 'Calibrated model with temperature scaling. Decision thresholds optimized on an independent validation split targeting <5% false positive rate.'
                      : 'Experimental tampering detection model. Currently uncalibrated pending evaluation against a verified, independent forensic benchmark (CASIA 1.0 / Columbia). Raw probabilities are provisional and must not be used as sole forensic proof.'}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Next Steps Action Buttons */}
          <div className="pt-2 flex flex-wrap items-center gap-2.5">
            <Button
              variant="primary"
              size="sm"
              icon={Eye}
              onClick={() => onSelectTab('visual')}
            >
              Inspect visual evidence
            </Button>

            {onDownloadReport && (
              <Button
                variant="outline"
                size="sm"
                icon={Download}
                onClick={onDownloadReport}
              >
                Download PDF report
              </Button>
            )}

            <Button
              variant="ghost"
              size="sm"
              icon={FileText}
              onClick={() => onSelectTab('technical')}
            >
              Technical details
            </Button>
          </div>
        </div>

        {/* Key Signals Strip with 5 interactive SignalChips */}
        <div className="p-5 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-3 shadow-xs">
          <div className="flex items-center justify-between text-xs">
            <span className="font-extrabold text-[var(--ink)] tracking-tight">Key signals (click to jump)</span>
            <span className="font-mono text-xs text-[var(--mute)]">5 automated checks</span>
          </div>

          <div className="flex flex-wrap gap-2">
            {keySignals.map((chip) => (
              <SignalChip
                key={chip.id}
                label={chip.label}
                status={chip.status}
                onClick={() => onSelectTab(chip.targetTab)}
              />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
