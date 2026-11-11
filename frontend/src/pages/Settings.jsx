/**
 * PRAMAANX - Architectural Laboratory Settings & Engine Configuration
 * Displays backend service connectivity, theme preferences, forensic parameters,
 * and active machine learning checkpoint specifications.
 */

import PageHeader from '../components/layout/PageHeader';
import Card from '../components/common/Card';
import Badge from '../components/common/Badge';
import ThemeToggle from '../components/common/ThemeToggle';
import { Server, Cpu, Sliders, Palette, Lock } from 'lucide-react';
import { FORENSIC_LIMITS, APP_VERSION } from '../utils/constants';
import { formatBytes } from '../utils/formatters';

export default function Settings() {
  return (
    <div className="space-y-8 max-w-5xl mx-auto pb-12">
      <PageHeader
        title="Laboratory Configuration & Parameters"
        subtitle="Operational parameters, interface appearance, threat scoring thresholds, and active machine learning checkpoint specifications."
        badge={
          <Badge variant="neutral" size="sm">
            CORE CONFIGURATION
          </Badge>
        }
      />

      {/* Interface & Theme Configuration */}
      <Card
        title="Interface & Visual Identity"
        subtitle="Customize theme modes and display preferences"
        headerIcon={Palette}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-subtle)] lab-card">
          <div className="space-y-1">
            <span className="text-xs font-mono font-bold text-[var(--text-primary)]">
              Color Theme Mode
            </span>
            <p className="text-xs text-[var(--text-muted)]">
              Choose between warm architectural Light mode, deep graphite Dark mode, or follow your OS system setting.
            </p>
          </div>
          <ThemeToggle compact={false} />
        </div>
      </Card>

      {/* Backend Operational Status */}
      <Card
        title="Forensic Backend Status"
        subtitle="Local REST API service health and runtime environment"
        headerIcon={Server}
        headerBadge={
          <Badge variant="low" size="sm" dot={true}>
            OPERATIONAL
          </Badge>
        }
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
          <div className="p-3.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <span className="text-[var(--text-muted)] block text-[10px] uppercase font-semibold">Service Endpoint</span>
            <span className="text-[var(--text-primary)] font-semibold mt-1 block">{import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'}</span>
          </div>
          <div className="p-3.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <span className="text-[var(--text-muted)] block text-[10px] uppercase font-semibold">API Version</span>
            <span className="text-[var(--text-primary)] font-semibold mt-1 block">v{APP_VERSION} (Phase 5)</span>
          </div>
          <div className="p-3.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <span className="text-[var(--text-muted)] block text-[10px] uppercase font-semibold">Model Host</span>
            <span className="text-[var(--text-primary)] font-semibold mt-1 block">Local CPU / PyTorch 2.6</span>
          </div>
          <div className="p-3.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <span className="text-[var(--text-muted)] block text-[10px] uppercase font-semibold">External API Calls</span>
            <span className="text-[var(--status-low)] font-semibold mt-1 block">0 (Zero-Cost / Strict)</span>
          </div>
        </div>
      </Card>

      {/* Model Inventory */}
      <Card
        title="Active Machine Learning Models"
        subtitle="Locally loaded weights and static feature extractors"
        headerIcon={Cpu}
      >
        <div className="space-y-3 font-mono">
          <div className="p-4 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)] flex flex-col sm:flex-row sm:items-center justify-between gap-3 lab-card">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-[var(--text-primary)] font-display">
                  EfficientNet-B0 Tamper Classifier
                </span>
                <Badge variant="low" size="sm">
                  Loaded
                </Badge>
              </div>
              <p className="text-xs text-[var(--text-muted)] mt-1">
                Dataset: CASIA 2.0 • Accuracy: ~71.37% • Input: 224x224 • Path: backend/models/image_tampering/pramaanx_efficientnet_best.pth
              </p>
            </div>
            <span className="text-xs text-[var(--text-primary)] font-semibold shrink-0 bg-[var(--bg-surface)] px-2.5 py-1 rounded-md border border-[var(--border-hairline)]">
              16.3 MB Checkpoint
            </span>
          </div>

          <div className="p-4 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)] flex flex-col sm:flex-row sm:items-center justify-between gap-3 lab-card">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold text-[var(--text-primary)] font-display">
                  Static Malicious PDF Feature Extractor
                </span>
                <Badge variant="medium" size="sm">
                  Weights Pending
                </Badge>
              </div>
              <p className="text-xs text-[var(--text-muted)] mt-1">
                22-dimensional structural vector (Obj/Stream ratios, JS tokens, /Launch, /OpenAction). Supervised XGBoost pending verified malware corpora.
              </p>
            </div>
            <span className="text-xs text-[var(--text-muted)] shrink-0 bg-[var(--bg-surface)] px-2.5 py-1 rounded-md border border-[var(--border-hairline)]">
              Zero Fabricated Predictions
            </span>
          </div>
        </div>
      </Card>

      {/* Forensic Limits & Thresholds */}
      <Card
        title="Pipeline Guardrails & Capacity"
        subtitle="Hardware resource and upload screening constraints"
        headerIcon={Sliders}
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 text-xs font-mono">
          <div className="p-3.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <span className="text-[var(--text-muted)] block text-[10px] uppercase font-semibold">Max Single File</span>
            <span className="text-[var(--text-primary)] font-semibold mt-1 block">
              {formatBytes(FORENSIC_LIMITS.MAX_SINGLE_FILE_BYTES)} (20 MB)
            </span>
          </div>
          <div className="p-3.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <span className="text-[var(--text-muted)] block text-[10px] uppercase font-semibold">Max Batch Allocation</span>
            <span className="text-[var(--text-primary)] font-semibold mt-1 block">
              {FORENSIC_LIMITS.MAX_BATCH_FILES} files ({formatBytes(FORENSIC_LIMITS.MAX_BATCH_TOTAL_BYTES)})
            </span>
          </div>
          <div className="p-3.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <span className="text-[var(--text-muted)] block text-[10px] uppercase font-semibold">ZIP Container Limits</span>
            <span className="text-[var(--text-primary)] font-semibold mt-1 block">
              {FORENSIC_LIMITS.MAX_ZIP_ENTRIES} entries / {formatBytes(FORENSIC_LIMITS.MAX_ZIP_UNCOMPRESSED_BYTES)} uncompressed
            </span>
          </div>
        </div>
      </Card>

      {/* Privacy Guarantee Note */}
      <div className="p-4 rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-subtle)] flex items-start gap-3 text-xs text-[var(--text-muted)]">
        <Lock className="w-4 h-4 text-[var(--status-low)] shrink-0 mt-0.5" />
        <p className="leading-relaxed font-mono text-[11px]">
          <strong className="text-[var(--text-primary)]">Strict Air-Gapped Operation:</strong> PRAMAANX contains zero external network telemetry, zero trackers, and zero calls to third-party commercial LLM providers. All neural models and heuristic parsers execute entirely within this local instance.
        </p>
      </div>
    </div>
  );
}
