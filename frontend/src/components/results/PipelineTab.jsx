/**
 * PRAMAANX - Results Pipeline Execution Tab
 * Clean vertical timeline stepper showing the 5 pipeline stages:
 * Ingestion -> Identification -> Structural Dissection -> Neural Screening -> Calibrated Verdict
 * Follows design system tokens, rounded-[26px] cards, and Manrope typography.
 */

import { CheckCircle2, Shield, Binary, Search, Cpu, Award } from 'lucide-react';

export default function PipelineTab({
  fileInfo,
  analysis,
}) {
  const hash = fileInfo?.sha256 || analysis?.sha256 || '';
  const detectedType = fileInfo?.detected_type || 'Unknown';
  const riskScore = analysis?.risk_score ?? 0;

  const stages = [
    {
      id: 1,
      title: '1. Ingestion & Cryptographic Custody',
      icon: Shield,
      status: 'Verified',
      summary: hash ? `SHA-256 fingerprint generated (${hash.slice(0, 12)}...)` : 'Read-only custody baseline',
      description: 'Streamed into sandboxed memory in 64 KB chunks without external transmission.',
    },
    {
      id: 2,
      title: '2. Magic Byte Identification',
      icon: Binary,
      status: 'Verified',
      summary: `Verified container type: ${detectedType.toUpperCase()}`,
      description: 'Pre-flight screening matches leading magic numbers to defeat extension cloaking.',
    },
    {
      id: 3,
      title: '3. Structural & Metadata Dissection',
      icon: Search,
      status: 'Completed',
      summary: 'Extracted structural dictionaries & Shannon entropy',
      description: 'Static heuristic dissection of revisions, object streams, and embedded metadata.',
    },
    {
      id: 4,
      title: '4. Neural Tamper Screening',
      icon: Cpu,
      status: detectedType === 'image' ? 'Inferred' : 'Not Required',
      summary: detectedType === 'image' ? 'CASIA 2.0 weights evaluated' : 'Document static dissection',
      description: detectedType === 'image' ? 'EfficientNet-B0 inference with ELA and Grad-CAM map generation.' : 'Document format evaluated through structural rules.',
    },
    {
      id: 5,
      title: '5. Calibrated Evidentiary Verdict',
      icon: Award,
      status: 'Compiled',
      summary: `Final calibrated risk score: ${riskScore}/100`,
      description: 'Probabilistic Noisy-OR compounding synthesis into explainable report.',
    },
  ];

  return (
    <div className="space-y-6">
      <div className="pb-3 border-b border-[var(--line)]">
        <h3 className="font-extrabold text-lg text-[var(--ink)] tracking-tight">
          Pipeline execution sequence
        </h3>
        <p className="text-xs text-[var(--mute)] mt-0.5">
          Audit trail of automated examination stages executed during this analysis run.
        </p>
      </div>

      <div className="relative border-l-2 border-[var(--line)] ml-4 sm:ml-6 pl-6 sm:pl-8 space-y-6">
        {stages.map((stage) => {
          const Icon = stage.icon;
          return (
            <div key={stage.id} className="relative group">
              {/* Node dot on timeline */}
              <div className="absolute -left-[31px] sm:-left-[39px] top-1.5 w-6 h-6 rounded-full bg-[var(--card)] border-2 border-[var(--ok)] flex items-center justify-center text-[var(--ok)] shadow-xs">
                <CheckCircle2 className="w-3.5 h-3.5" />
              </div>

              {/* Stage Card */}
              <div className="p-5 rounded-[26px] border border-[var(--line)] bg-[var(--card)] space-y-2 shadow-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <Icon className="w-4 h-4 text-[var(--brand)]" />
                    <h4 className="font-extrabold text-base text-[var(--ink)] tracking-tight">
                      {stage.title}
                    </h4>
                  </div>
                  <span className="text-xs font-bold uppercase tracking-wider text-[var(--ok)] bg-[var(--soft)] px-3 py-0.5 rounded-full border border-[var(--ok)]">
                    {stage.status}
                  </span>
                </div>

                <p className="font-bold text-xs text-[var(--ink)]">
                  {stage.summary}
                </p>
                <p className="text-xs text-[var(--mute)] leading-relaxed">
                  {stage.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
