/**
 * PRAMAANX - Digital Forensics Knowledge Hub (Learn)
 * Educational portal explaining forensic methods, machine learning models, and indicators.
 * Provides dual-level explanations:
 * Level 1: Simple explanation (Beginners & Students)
 * Level 2: Advanced technical explanation (Forensic Analysts & Researchers)
 */

import { useState } from 'react';
import { Link } from 'react-router-dom';
import PageHeader from '../components/layout/PageHeader';
import Card from '../components/common/Card';
import Badge from '../components/common/Badge';
import Button from '../components/common/Button';
import {
  BookOpen,
  Search,
  FileSearch,
  Binary,
  Hash,
  Clock,
  Layers,
  FileCode,
  ShieldAlert,
  Cpu,
  Zap,
  Activity,
  Archive,
  CheckCircle2,
  ArrowRight,
  Sparkles,
} from 'lucide-react';
import { ROUTES } from '../utils/constants';

const TOPIC_CATEGORIES = [
  { id: 'ALL', label: 'All Topics' },
  { id: 'FUNDAMENTALS', label: 'Fundamentals' },
  { id: 'DOCUMENTS', label: 'Document Forensics' },
  { id: 'IMAGES', label: 'Image Forensics' },
  { id: 'ARCHIVES', label: 'Archive Safety' },
  { id: 'RISK', label: 'Risk & Statistics' },
];

const FORENSIC_TOPICS = [
  {
    id: 'fundamentals',
    category: 'FUNDAMENTALS',
    title: 'Digital Forensics Fundamentals',
    icon: BookOpen,
    analyzerRef: 'Core Architecture',
    simple:
      'Digital forensics is the scientific examination of digital files to determine their origin, integrity, history, and authenticity without altering the original evidence.',
    advanced:
      'Digital forensics adheres to ISO/IEC 27037 standards for digital evidence handling: acquisition, preservation, analysis, and reporting. Evidence integrity is preserved through read-only access and cryptographic verification.',
  },
  {
    id: 'magic-bytes',
    category: 'FUNDAMENTALS',
    title: 'File Signatures & Magic Bytes',
    icon: Binary,
    analyzerRef: 'File Identification (common.py)',
    simple:
      'A file extension (like .pdf or .png) is just a label that can be renamed. Magic bytes are the actual initial bytes of a file that truthfully identify what kind of file it is.',
    advanced:
      'File identification inspects leading magic numbers (e.g., %PDF- for PDF, \x89PNG\r\n\x1a\n for PNG, PK\x03\x04 for ZIP/Office, MZ for PE executables). Mismatches between claimed extension and content bytes expose extension-spoofing vectors.',
  },
  {
    id: 'sha256',
    category: 'FUNDAMENTALS',
    title: 'SHA-256 Cryptographic Hashing',
    icon: Hash,
    analyzerRef: 'SHA-256 Engine (common.py)',
    simple:
      'A cryptographic hash is like a unique digital fingerprint. If even a single character or pixel changes in the file, the hash changes completely.',
    advanced:
      'SHA-256 computes a deterministic 256-bit (32-byte) digest using the Merkle-Damgård construction. It guarantees collision resistance for evidence integrity verification. Note: A valid hash proves integrity since acquisition, but does not prove the original content was unmodified prior to acquisition.',
  },
  {
    id: 'metadata',
    category: 'FUNDAMENTALS',
    title: 'Metadata Analysis & Timelines',
    icon: Clock,
    analyzerRef: 'Metadata Extractors',
    simple:
      'Metadata is "data about data" — such as author name, software used, and creation or modification dates. Forensic analysis checks if these dates make logical sense.',
    advanced:
      'Parses structural metadata dictionaries (PDF Info/XMP, OpenXML core.xml, EXIF tags). Detects anomalies such as timestamp inversion (file modified before it was created) or software fingerprints of known image manipulation tools.',
  },
  {
    id: 'entropy',
    category: 'FUNDAMENTALS',
    title: 'Shannon Entropy & Byte Distribution',
    icon: Activity,
    analyzerRef: 'Entropy Calculator (common.py)',
    simple:
      'Entropy measures how random the data inside a file is, from 0 to 8. Normal plain text has lower entropy; compressed or encrypted data has high entropy.',
    advanced:
      'Calculates Shannon entropy: H = -sum(p_i * log2(p_i)). Plaintext spans 3.5 - 5.0; compiled binaries span 5.5 - 6.8; compressed/encrypted payloads approach 7.2 - 8.0. High entropy in unexpected file segments indicates packed or obfuscated code.',
  },
  {
    id: 'pdf-structure',
    category: 'DOCUMENTS',
    title: 'PDF Internal Object Structure',
    icon: Layers,
    analyzerRef: 'PDF Structural Analyzer (pdf.py)',
    simple:
      'A PDF is not a flat image; it is an internal tree of objects, dictionaries, streams, and revisions. PRAMAANX inspects this tree to find hidden sections.',
    advanced:
      'Parses PDF cross-reference tables (XREF), indirect object dictionaries (/Obj), and revision tails (%%EOF markers). Multiple incremental revisions can reveal overwritten text, hidden annotations, or appended content.',
  },
  {
    id: 'pdf-javascript',
    category: 'DOCUMENTS',
    title: 'Embedded JavaScript & Launch Actions',
    icon: FileCode,
    analyzerRef: 'PDF Analyzer (pdf.py)',
    simple:
      'PDFs can contain scripts that run automatically when opened. While sometimes used in legitimate forms, attackers use them to execute malicious commands.',
    advanced:
      'Screens PDF name trees and dictionaries for /JavaScript, /JS, /Launch, /OpenAction, and /AA keys. PRAMAANX extracts the script text for static inspection without executing it in the operating system.',
  },
  {
    id: 'office-macros',
    category: 'DOCUMENTS',
    title: 'Office OpenXML & VBA Macros',
    icon: ShieldAlert,
    analyzerRef: 'Office Analyzer (office.py)',
    simple:
      'Modern Word and Excel files are zipped collections of XML files. If a document secretly contains automated macros or links to external templates, it is flagged.',
    advanced:
      'Unpacks OpenXML archives to inspect relationships (_rels), word/vbaProject.bin, and customXml. Screens for remote template injection (TargetMode="External"), veryHidden worksheet states, and macro cloaking.',
  },
  {
    id: 'image-tampering',
    category: 'IMAGES',
    title: 'Image Splicing & Tampering Detection',
    icon: Cpu,
    analyzerRef: 'EfficientNet-B0 (image.py)',
    simple:
      'Image tampering includes cut-and-paste splicing, object removal, or copy-move forgery. Neural networks detect tiny pixel inconsistencies that the human eye misses.',
    advanced:
      'Runs a PyTorch EfficientNet-B0 convolutional neural network fine-tuned on the CASIA 2.0 dataset (approx 71.37% test accuracy). Analyzes high-frequency residual spatial features to estimate tamper probability.',
  },
  {
    id: 'gradcam',
    category: 'IMAGES',
    title: 'Grad-CAM Attention Heatmaps',
    icon: Sparkles,
    analyzerRef: 'Grad-CAM Engine (image.py)',
    simple:
      'Grad-CAM highlights the exact spots on an image that caused the AI model to suspect tampering, showing warm red/yellow colors where the anomaly was found.',
    advanced:
      'Gradient-weighted Class Activation Mapping computes gradients of the target class score with respect to feature maps of the final convolutional block. Rectified linear combination yields a coarse localization heatmap of influential regions.',
  },
  {
    id: 'ela',
    category: 'IMAGES',
    title: 'Error Level Analysis (ELA)',
    icon: Zap,
    analyzerRef: 'ELA Processor (image.py)',
    simple:
      'When you save a JPEG image, it loses a small amount of quality evenly across the whole image. If a new object was pasted in later, its error level will stand out.',
    advanced:
      'Re-compresses the image at a standardized 95% JPEG quality factor and computes absolute pixel difference matrices. Spliced elements or multi-generation resaves exhibit distinct discrete cosine transform (DCT) error variances.',
  },
  {
    id: 'risk-scoring',
    category: 'RISK',
    title: 'Noisy-OR Probabilistic Risk Scoring',
    icon: Activity,
    analyzerRef: 'Risk Evaluator (common.py)',
    simple:
      'Rather than simply adding numbers together, PRAMAANX combines multiple security indicators so that multiple independent warnings produce a balanced 0–100 score.',
    advanced:
      'Implements the probabilistic Noisy-OR combination formula: Risk = round((1 - prod(1 - w_i)) * 100), where each finding carries an empirical weight w_i in [0, 1]. Compounding models cumulative evidence without linear score inflation.',
  },
  {
    id: 'archive-safety',
    category: 'ARCHIVES',
    title: 'ZIP Slip & Zip Bomb Protection',
    icon: Archive,
    analyzerRef: 'ZIP Safety Validator (common.py)',
    simple:
      'ZIP files can hide attacks that overwrite critical system files when unzipped, or expand into gigabytes of data to freeze your computer. PRAMAANX checks archives before extracting them.',
    advanced:
      'Screens ZIP entry central directories before extraction: validates canonical destination paths to block directory traversal attacks (Zip Slip: ../../), limits entry count, and enforces uncompressed size ratios to neutralize Zip Bombs.',
  },
];

export default function Learn() {
  const [activeCategory, setActiveCategory] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [viewLevel, setViewLevel] = useState('simple'); // 'simple' | 'advanced'

  const filteredTopics = FORENSIC_TOPICS.filter((topic) => {
    const matchesCategory =
      activeCategory === 'ALL' || topic.category === activeCategory;
    const matchesSearch =
      topic.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      topic.simple.toLowerCase().includes(searchTerm.toLowerCase()) ||
      topic.advanced.toLowerCase().includes(searchTerm.toLowerCase()) ||
      topic.analyzerRef.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="space-y-8 max-w-5xl mx-auto pb-12">
      {/* Header */}
      <PageHeader
        title="Digital Forensics Knowledge Hub"
        subtitle="Learn the scientific principles, heuristic rules, and machine learning methods powering PRAMAANX forensic analysis."
        badge={
          <Badge variant="neutral" size="sm">
            FORENSIC EDUCATION
          </Badge>
        }
      />

      {/* Control Bar: Search & Level Toggle */}
      <Card bodyClassName="p-4">
        <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
          {/* Search Bar */}
          <div className="relative w-full md:w-80">
            <Search className="absolute left-3 top-2.5 w-4 h-4 text-[var(--text-muted)]" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search topics (e.g. SHA-256, Grad-CAM, Zip Slip)..."
              className="w-full pl-9 pr-4 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] placeholder-[#94A3B8] border border-[var(--border-hairline)] rounded-lg focus:outline-none focus:border-[#2563EB]"
            />
          </div>

          {/* Level Toggle: Simple View vs Advanced Technical View */}
          <div className="flex items-center gap-2 w-full md:w-auto justify-between md:justify-end">
            <span className="text-xs text-[var(--text-muted)] font-medium">Depth Level:</span>
            <div className="flex items-center p-0.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
              <button
                type="button"
                onClick={() => setViewLevel('simple')}
                className={`px-3 py-1 text-xs font-semibold rounded-md transition-all ${
                  viewLevel === 'simple'
                    ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-xs'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                }`}
              >
                Simple View (Beginner)
              </button>
              <button
                type="button"
                onClick={() => setViewLevel('advanced')}
                className={`px-3 py-1 text-xs font-semibold rounded-md transition-all ${
                  viewLevel === 'advanced'
                    ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-xs'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                }`}
              >
                Advanced Technical (Analyst)
              </button>
            </div>
          </div>
        </div>

        {/* Category Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5 pt-3 mt-3 border-t border-[var(--border-hairline)]">
          {TOPIC_CATEGORIES.map((cat) => (
            <button
              key={cat.id}
              type="button"
              onClick={() => setActiveCategory(cat.id)}
              className={`px-2.5 py-1 text-[11px] font-medium rounded-md transition-colors ${
                activeCategory === cat.id
                  ? 'bg-[#0F172A] text-white shadow-xs'
                  : 'text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-subtle)]'
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </Card>

      {/* Core Principle Notice */}
      <div className="p-4 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)] flex items-start gap-3 text-xs text-[var(--text-muted)]">
        <CheckCircle2 className="w-4 h-4 text-[var(--accent-cobalt)] shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-[var(--text-primary)] font-semibold">
            &ldquo;Simple to understand. Deep enough to investigate.&rdquo;
          </strong>{' '}
          Every concept here directly maps to an active analyzer in the PRAMAANX engine. You can toggle between beginner explanations and advanced mathematical logic at any time.
        </div>
      </div>

      {/* Topics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredTopics.map((topic) => {
          const Icon = topic.icon;
          return (
            <div
              key={topic.id}
              className="rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] p-5 shadow-xs hover:border-[var(--border-strong)] transition-all flex flex-col justify-between space-y-4"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="w-8 h-8 rounded-lg bg-[var(--accent-subtle)] border border-[var(--accent-border)] flex items-center justify-center text-[var(--accent-cobalt)]">
                    <Icon className="w-4 h-4" />
                  </div>
                  <span className="text-[10px] font-mono text-[var(--text-muted)] bg-[var(--bg-subtle)] px-2 py-0.5 rounded border border-[var(--border-hairline)]">
                    {topic.analyzerRef}
                  </span>
                </div>

                <div>
                  <h3 className="text-sm font-bold text-[var(--text-primary)]">{topic.title}</h3>
                  <div className="mt-2 text-xs leading-relaxed text-[#334155]">
                    {viewLevel === 'simple' ? (
                      <p>{topic.simple}</p>
                    ) : (
                      <div className="space-y-1.5">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--accent-cobalt)] block">
                          Technical Specification
                        </span>
                        <p className="font-mono text-[11px] text-[#1E293B] bg-[var(--bg-subtle)] p-2.5 rounded-lg border border-[var(--border-hairline)]">
                          {topic.advanced}
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div className="pt-3 border-t border-[var(--border-hairline)] flex items-center justify-between text-xs">
                <span className="text-[11px] text-[var(--text-muted)]">
                  Category: <strong className="text-[var(--text-primary)]">{topic.category}</strong>
                </span>
                <Link
                  to={ROUTES.ANALYZE}
                  className="text-[11px] font-medium text-[var(--accent-cobalt)] hover:text-[#1D4ED8] flex items-center gap-1"
                >
                  Inspect in Analyzer <ArrowRight className="w-3 h-3" />
                </Link>
              </div>
            </div>
          );
        })}
      </div>

      {filteredTopics.length === 0 && (
        <div className="text-center py-12 bg-[var(--bg-surface)] rounded-xl border border-[var(--border-hairline)] space-y-2">
          <BookOpen className="w-8 h-8 text-[var(--text-subtle)] mx-auto" />
          <h4 className="text-sm font-bold text-[var(--text-primary)]">No Matching Educational Topics</h4>
          <p className="text-xs text-[var(--text-muted)]">Try searching with a different forensic term.</p>
        </div>
      )}

      {/* Practical Action Footer */}
      <Card
        title="Ready to Apply This Knowledge?"
        subtitle="Submit a document or image to observe these forensic methods in real-time."
        headerIcon={FileSearch}
        action={
          <Button
            variant="primary"
            size="sm"
            icon={ArrowRight}
            iconPosition="right"
            onClick={() => (window.location.href = ROUTES.ANALYZE)}
          >
            Open Evidence Analyzer
          </Button>
        }
      >
        <p className="text-xs text-[var(--text-muted)] leading-relaxed">
          PRAMAANX analyzes uploaded files locally using the exact algorithms described in this guide. No data is sent to external servers or third-party AI models.
        </p>
      </Card>
    </div>
  );
}

