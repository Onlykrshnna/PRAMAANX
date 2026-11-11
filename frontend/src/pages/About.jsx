/**
 * PRAMAANX - About & Architecture Page
 * Explains the platform mission, zero-cost self-owned AI policy, and open-source forensics stack.
 */

import PageHeader from '../components/layout/PageHeader';
import Card from '../components/common/Card';
import Badge from '../components/common/Badge';
import { Shield, Cpu, Lock, CheckCircle2, Code2 } from 'lucide-react';
import { APP_VERSION } from '../utils/constants';

export default function About() {
  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      <PageHeader
        title="About PRAMAANX"
        subtitle="An open-source, portfolio-grade digital document and image forensics platform built for cybersecurity research and evidence verification."
        badge={
          <Badge variant="neutral" size="sm">
            v{APP_VERSION}
          </Badge>
        }
      />

      {/* Core Mission */}
      <Card title="The PRAMAANX Philosophy" headerIcon={Shield}>
        <div className="space-y-4 text-sm text-[var(--text-secondary)] leading-relaxed">
          <p>
            The name <strong className="text-[var(--text-primary)]">PRAMAANX</strong> originates from the Sanskrit term <em>Pramāna</em>, meaning &ldquo;proof,&rdquo; &ldquo;means of valid knowledge,&rdquo; or verifiable evidence.
          </p>
          <p>
            Traditional forensic tools are often closed-source, expensive enterprise software or dependent on cloud APIs that require sending confidential files to third parties. PRAMAANX was designed to prove that production-grade digital forensics can be built on free, open-source Python primitives and self-owned, local machine learning models without spending a single dollar on external SaaS APIs.
          </p>
        </div>
      </Card>

      {/* Strict Zero-Cost & Privacy Policy */}
      <Card
        title="Strict Zero-Cost & Privacy Policy"
        subtitle="100% On-Premise Execution — Zero Cloud API Dependence"
        headerIcon={Lock}
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div className="p-3.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <div className="flex items-center gap-2 text-[var(--text-primary)] font-semibold mb-1">
              <CheckCircle2 className="w-4 h-4 text-[var(--status-low)]" />
              No Commercial LLM APIs
            </div>
            <p className="text-[var(--text-muted)]">
              Does not depend on OpenAI, Anthropic Claude, or Google Gemini. Deterministic reporting prevents hallucinations.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <div className="flex items-center gap-2 text-[var(--text-primary)] font-semibold mb-1">
              <CheckCircle2 className="w-4 h-4 text-[var(--status-low)]" />
              Local Neural Inference
            </div>
            <p className="text-[var(--text-muted)]">
              EfficientNet-B0 trained on CASIA 2.0 runs locally on your CPU/GPU using standard PyTorch weights (16.3 MB).
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <div className="flex items-center gap-2 text-[var(--text-primary)] font-semibold mb-1">
              <CheckCircle2 className="w-4 h-4 text-[var(--status-low)]" />
              Zero Third-Party Data Transmission
            </div>
            <p className="text-[var(--text-muted)]">
              Uploaded files are streamed into temporary sandbox memory and unlinked immediately after analysis.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            <div className="flex items-center gap-2 text-[var(--text-primary)] font-semibold mb-1">
              <CheckCircle2 className="w-4 h-4 text-[var(--status-low)]" />
              No Fabricated Findings or Hallucinations
            </div>
            <p className="text-[var(--text-muted)]">
              Adheres strictly to project integrity rules: models pending training (such as XGBoost) are marked as pending rather than fabricated.
            </p>
          </div>
        </div>
      </Card>

      {/* Technology Stack Architecture */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card title="Backend & Forensic Engines" headerIcon={Code2}>
          <ul className="space-y-2.5 text-xs text-[var(--text-secondary)]">
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#2563EB] mt-1.5 shrink-0" />
              <span><strong>FastAPI & Python 3.11:</strong> High-throughput asynchronous backend streaming files in 64 KB chunks.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#2563EB] mt-1.5 shrink-0" />
              <span><strong>PyMuPDF & Pikepdf:</strong> Deep AST document parsing, token scanning, and revision count.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#2563EB] mt-1.5 shrink-0" />
              <span><strong>python-docx & openpyxl:</strong> OpenXML relationship inspection, remote template injection (CVE-2017-0199).</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#2563EB] mt-1.5 shrink-0" />
              <span><strong>Probabilistic Noisy-OR:</strong> Multi-engine threat scoring formula compounding independent finding weights.</span>
            </li>
          </ul>
        </Card>

        <Card title="Computer Vision & Deep Learning" headerIcon={Cpu}>
          <ul className="space-y-2.5 text-xs text-[var(--text-secondary)]">
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#2563EB] mt-1.5 shrink-0" />
              <span><strong>EfficientNet-B0 (PyTorch):</strong> Fine-tuned on the CASIA 2.0 image tampering dataset (~71.37% test accuracy).</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#2563EB] mt-1.5 shrink-0" />
              <span><strong>Grad-CAM:</strong> Gradient-weighted activation heatmaps highlighting manipulated regions.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#2563EB] mt-1.5 shrink-0" />
              <span><strong>Error Level Analysis (ELA):</strong> JPEG compression differential reconstruction at 95% quality.</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#2563EB] mt-1.5 shrink-0" />
              <span><strong>Steganography & Trailing Data:</strong> Scans byte offsets beyond JPEG EOI and PNG IEND markers.</span>
            </li>
          </ul>
        </Card>
      </div>
    </div>
  );
}
