/**
 * PRAMAANX - Forensic Explainability & Taxonomy Helpers
 * Provides scientifically responsible dual-level interpretations:
 * - Simple View: 10-second plain-English summary, file-specific checklist, AI assessment, clean finding cards.
 * - Technical View: Exact analyzer names, detection methods, byte offsets, Noisy-OR weights, and scientific limitations.
 *
 * Distinguishes:
 * 1. Confirmed Structural Observations
 * 2. Statistical Anomalies
 * 3. Heuristic Findings
 * 4. Machine-Learning Predictions
 * 5. Inconclusive Results
 */

export const TAXONOMY_TYPES = {
  STRUCTURAL: {
    key: 'structural',
    label: 'Structural Observation',
    badgeVariant: 'neutral',
    dotColor: '#2563EB',
    description: 'Direct physical fact verified in the file byte stream or container.',
  },
  STATISTICAL: {
    key: 'statistical',
    label: 'Statistical Anomaly',
    badgeVariant: 'medium',
    dotColor: '#B45309',
    description: 'Quantitative metric variance (entropy, compression differentials).',
  },
  HEURISTIC: {
    key: 'heuristic',
    label: 'Heuristic Indicator',
    badgeVariant: 'high',
    dotColor: '#DC2626',
    description: 'Rule-based pattern matching known evasion or attack techniques.',
  },
  MACHINE_LEARNING: {
    key: 'machine_learning',
    label: 'Machine-Learning Prediction',
    badgeVariant: 'metallic',
    dotColor: '#7C3AED',
    description: 'Statistical classification from trained neural or ensemble weights.',
  },
  INCONCLUSIVE: {
    key: 'inconclusive',
    label: 'Inconclusive Result',
    badgeVariant: 'neutral',
    dotColor: '#64748B',
    description: 'Neutral observation or missing data; does not establish tampering.',
  },
};

/**
 * Documented & provisional working thresholds for the CASIA 2.0-trained EfficientNet-B0 model.
 * NOTE: These thresholds are explicitly provisional until formal ROC curve calibration and
 * validation are conducted in Milestone G.
 */
export const ML_THRESHOLDS = {
  LOW_MAX: 0.35,       // Provisional (< 0.35: low tamper likelihood)
  UNCERTAIN_MAX: 0.65, // Provisional (0.35 - 0.65: inconclusive / uncertainty zone)
  HIGH_MIN: 0.65,      // Provisional (> 0.65: elevated tamper likelihood)
  IS_PROVISIONAL: true,
  VALIDATION_MILESTONE: 'Milestone G',
  PROVISIONAL_NOTICE:
    'Provisional heuristic boundaries (35% / 65%) pending rigorous cross-dataset ROC calibration and empirical validation in Milestone G.',
};

/**
 * Categorizes a forensic finding into one of the 5 scientific taxonomy types.
 */
export function classifyFindingTaxonomy(finding) {
  if (finding.category && TAXONOMY_TYPES[finding.category.toUpperCase()]) {
    return TAXONOMY_TYPES[finding.category.toUpperCase()];
  }

  const title = (finding.title || finding.name || '').toLowerCase();
  const detail = (finding.detail || finding.description || '').toLowerCase();

  // Machine Learning
  if (
    title.includes('machine learning') ||
    title.includes('efficientnet') ||
    title.includes('tamper probability') ||
    title.includes('neural') ||
    title.includes('grad-cam') ||
    title.includes('xgboost') ||
    detail.includes('efficientnet')
  ) {
    return TAXONOMY_TYPES.MACHINE_LEARNING;
  }

  // Statistical Anomalies
  if (
    title.includes('entropy') ||
    title.includes('error level') ||
    title.includes('ela') ||
    title.includes('variance') ||
    title.includes('distribution')
  ) {
    return TAXONOMY_TYPES.STATISTICAL;
  }

  // Inconclusive / Neutral
  if (
    title.includes('failure') ||
    title.includes('incomplete') ||
    title.includes('missing preamble') ||
    title.includes('unsupported') ||
    title.includes('stripped metadata')
  ) {
    return TAXONOMY_TYPES.INCONCLUSIVE;
  }

  // Confirmed Structural Observations
  if (
    title.includes('signature') ||
    title.includes('magic byte') ||
    title.includes('revision') ||
    title.includes('%%eof') ||
    title.includes('javascript') ||
    title.includes('vba macro') ||
    title.includes('ole') ||
    title.includes('sheet') ||
    title.includes('slide') ||
    title.includes('zip slip') ||
    title.includes('bomb') ||
    title.includes('embedded file') ||
    title.includes('appended data') ||
    title.includes('spoofing') ||
    title.includes('mismatch')
  ) {
    return TAXONOMY_TYPES.STRUCTURAL;
  }

  // Default to Heuristic Indicator
  return TAXONOMY_TYPES.HEURISTIC;
}

/**
 * Extracts exact evidence traceability indicators from real finding evidence payloads.
 * Strictly avoids fabricating any values; only extracts genuine values emitted by backend analyzers.
 */
export function extractTraceabilityItems(finding) {
  const ev = finding?.evidence || {};
  const items = [];

  // 1. Byte Offsets
  if (Array.isArray(ev.byte_offsets) && ev.byte_offsets.length > 0) {
    items.push({
      type: 'offset',
      label: 'Byte Offsets',
      value:
        ev.byte_offsets.slice(0, 5).map((o) => `${o} (0x${Number(o).toString(16).toUpperCase()})`).join(', ') +
        (ev.byte_offsets.length > 5 ? ` +${ev.byte_offsets.length - 5} more` : ''),
    });
  } else if (Array.isArray(ev.eof_byte_offsets) && ev.eof_byte_offsets.length > 0) {
    items.push({
      type: 'offset',
      label: '%%EOF Markers',
      value: ev.eof_byte_offsets.map((o) => `${o} (0x${Number(o).toString(16).toUpperCase()})`).join(', '),
    });
  } else if (ev.byte_offset !== undefined) {
    items.push({
      type: 'offset',
      label: 'Byte Offset',
      value: `${ev.byte_offset} (0x${Number(ev.byte_offset).toString(16).toUpperCase()})`,
    });
  } else if (ev.eoi_offset !== undefined) {
    items.push({
      type: 'offset',
      label: 'JPEG EOI Marker',
      value: `${ev.eoi_offset} (0x${Number(ev.eoi_offset).toString(16).toUpperCase()})`,
    });
  } else if (ev.iend_offset !== undefined) {
    items.push({
      type: 'offset',
      label: 'PNG IEND Chunk',
      value: `${ev.iend_offset} (0x${Number(ev.iend_offset).toString(16).toUpperCase()})`,
    });
  }

  // 2. Container / Archive Paths
  const containerPath =
    ev.container_path ||
    ev.file_path_in_zip ||
    ev.vba_entry ||
    ev.rels_file ||
    ev.xml_entry ||
    ev.dangerous_entry ||
    ev.malicious_entry ||
    ev.symlink_entry ||
    ev.media_entry;
  if (containerPath) {
    items.push({
      type: 'path',
      label: 'Container Path',
      value: String(containerPath),
    });
  }

  // 3. Targets and Remote URLs
  if (ev.remote_template_url) {
    items.push({
      type: 'url',
      label: 'Remote Template Target',
      value: String(ev.remote_template_url),
    });
  } else if (ev.target) {
    items.push({
      type: 'url',
      label: 'Relationship Target',
      value: String(ev.target),
    });
  } else if (Array.isArray(ev.suspicious_uris) && ev.suspicious_uris.length > 0) {
    items.push({
      type: 'url',
      label: 'Target URI',
      value: ev.suspicious_uris.slice(0, 3).join(', '),
    });
  }

  // 4. Hidden Sheets / Slides
  if (Array.isArray(ev.very_hidden_sheets) && ev.very_hidden_sheets.length > 0) {
    items.push({
      type: 'sheet',
      label: 'VeryHidden Sheet(s)',
      value: ev.very_hidden_sheets.join(', '),
    });
  } else if (Array.isArray(ev.hidden_sheets) && ev.hidden_sheets.length > 0) {
    items.push({
      type: 'sheet',
      label: 'Hidden Sheet(s)',
      value: ev.hidden_sheets.join(', '),
    });
  } else if (ev.hidden_slide_count) {
    items.push({
      type: 'sheet',
      label: 'Hidden Presentation Slides',
      value: `${ev.hidden_slide_count} slide(s)`,
    });
  }

  // 5. Software / Editor Attribution
  if (ev.software) {
    items.push({
      type: 'software',
      label: 'EXIF Software Signature',
      value: String(ev.software),
    });
  } else if (Array.isArray(ev.tools_identified) && ev.tools_identified.length > 0) {
    items.push({
      type: 'software',
      label: 'Identified Design Tools',
      value: ev.tools_identified.join(', '),
    });
  }

  // 6. Machine Learning Model Verdict
  if (ev.ml_evidence && typeof ev.ml_evidence === 'object') {
    const ml = ev.ml_evidence;
    items.push({
      type: 'ml',
      label: 'ML Classifier Verdict',
      value: `${ml.architecture || 'EfficientNet-B0'} (${Math.round((ml.confidence || 0) * 100)}% confidence)`,
    });
  } else if (ev.architecture) {
    items.push({
      type: 'ml',
      label: 'Model Architecture',
      value: `${ev.architecture} (${Math.round((ev.confidence || 0) * 100)}% confidence)`,
    });
  }

  return items;
}

/**
 * Builds structured plain-language and technical explanations for a finding.
 */
export function explainFinding(finding) {
  const taxonomy = classifyFindingTaxonomy(finding);
  const title = (finding.title || finding.name || '').toLowerCase();
  const rawDetail = finding.detail || finding.description || '';
  const traceabilityItems = extractTraceabilityItems(finding);

  let whatWasExamined = 'The internal byte structure and headers of the file were inspected.';
  let whatWasFound = rawDetail || 'An anomalous indicator was recorded by the analysis engine.';
  let whyItMatters = 'Unexpected file characteristics can indicate deliberate evasion, hiding of code, or data tampering.';
  let whatToDoNext = 'Examine the raw technical parameters to verify if this behavior was intentional.';
  let engineName = 'PRAMAANX Core Forensic Engine';
  let detectionMethod = 'Static heuristic pattern inspection';
  let confidenceLabel = 'Deterministic Rule Check';
  let limitations = 'Rule-based indicators identify known patterns but require contextual review by the investigator.';

  // 1. Extension Spoofing
  if (title.includes('spoofing') || title.includes('mismatch') || title.includes('disguise')) {
    whatWasExamined = 'The declared file extension was compared against the actual binary magic bytes in the file header.';
    whatWasFound = 'The file claims to be one format, but its internal bytes prove it is a completely different file type (e.g. an executable).';
    whyItMatters = 'Attackers disguise executable files with harmless extensions to trick users into opening malware.';
    whatToDoNext = 'Do not run or open this file. Isolate it in a secure sandbox and verify its original source.';
    engineName = 'Signature & Magic Byte Analyzer (common.py)';
    detectionMethod = 'Byte header offset matching against standard RFC/ISO file signatures';
    confidenceLabel = 'Exact Header Signature Match';
    limitations = 'Magic-byte matching identifies header signatures; it does not evaluate payload execution safety.';
  }

  // 2. High Shannon Entropy
  else if (title.includes('high shannon entropy')) {
    whatWasExamined = 'The mathematical randomness of byte distribution was measured across the entire file.';
    whatWasFound = 'The byte randomness is near the theoretical maximum (close to 8.0 bits per byte).';
    whyItMatters = 'In an uncompressed file, near-maximal entropy indicates encrypted data, compressed shellcode, or packed software designed to bypass security scanners.';
    whatToDoNext = 'Determine whether this file is expected to be encrypted or packed. Inspect byte sections for obfuscation.';
    engineName = 'Shannon Entropy Engine (common.py)';
    detectionMethod = 'Shannon H-formula calculation: -sum(p_i * log2(p_i)) across 256 byte states';
    confidenceLabel = 'Exact Mathematical Measurement';
    limitations = 'High entropy is normal for compressed media (JPEG, PNG, ZIP). In uncompressed formats, it signals encryption or packing.';
  }

  // 3. Low Shannon Entropy
  else if (title.includes('low shannon entropy')) {
    whatWasExamined = 'The byte diversity of the file was analyzed.';
    whatWasFound = 'The file contains very little variation, repeating the same byte sequences continually.';
    whyItMatters = 'Extremely low entropy in a file typically indicates zero-byte padding, null filling, or corrupt storage.';
    whatToDoNext = 'Check if the file was corrupted during transfer or truncated before upload.';
    engineName = 'Shannon Entropy Engine (common.py)';
    detectionMethod = 'Shannon H-formula calculation';
    confidenceLabel = 'Exact Mathematical Measurement';
    limitations = 'Measures uniformity only; does not pinpoint corruption root causes.';
  }

  // 4. Inverted Modification Timestamp
  else if (title.includes('inverted') || title.includes('chronology')) {
    whatWasExamined = 'Creation and last modified timestamps inside document metadata streams were compared.';
    whatWasFound = 'The last modified timestamp is chronologically earlier than the creation timestamp.';
    whyItMatters = 'Inversion is a classic hallmark of document backdating, metadata scrubbing, or cloning from a newer template.';
    whatToDoNext = 'Inspect the file system timestamps and compare them with the document metadata timestamps.';
    engineName = 'Metadata Chronology Analyzer (pdf.py / office.py)';
    detectionMethod = 'Chronological differential comparison between CreationDate and ModDate';
    confidenceLabel = 'Deterministic Timestamp Comparison';
    limitations = 'Inaccurate system clocks on author workstations can occasionally produce non-malicious discrepancies.';
  }

  // 5. PDF JavaScript
  else if (title.includes('javascript') || title.includes('/js')) {
    whatWasExamined = 'The internal PDF dictionary tree was scanned for script execution commands.';
    whatWasFound = 'Embedded JavaScript code was detected inside this PDF document.';
    whyItMatters = 'While legitimate forms use JavaScript, attackers abuse it to download external payloads or exploit PDF reader vulnerabilities.';
    whatToDoNext = 'Review the extracted script text in a script-disabled PDF reader. Do not enable JavaScript execution.';
    engineName = 'PDF Structural Analyzer (pdf.py)';
    detectionMethod = 'Regex dictionary traversal for /JavaScript, /JS, /OpenAction, and /AA keys with byte offset indexing';
    confidenceLabel = 'Deterministic Byte Token Match';
    limitations = 'Identifies script presence; static analysis does not dynamically execute scripts.';
  }

  // 6. PDF Incremental Revisions
  else if (title.includes('revision') || title.includes('%%eof')) {
    whatWasExamined = 'The document was inspected for multiple revision tails (%%EOF markers).';
    whatWasFound = 'The document has been revised or modified multiple times after its original creation.';
    whyItMatters = 'Multiple revisions can reveal edited contract numbers, overwritten dates, or modifications made without a visible audit trail.';
    whatToDoNext = 'Compare the initial revision with the final revision to observe what content was added or masked.';
    engineName = 'PDF Structural Revision Screener (pdf.py)';
    detectionMethod = 'Linear byte search for %%EOF markers and trailing cross-reference tables';
    confidenceLabel = 'Deterministic Byte Structure Match';
    limitations = 'Incremental updates are standard in digitally signed PDFs; presence does not automatically indicate forgery.';
  }

  // 7. PDF Launch Actions
  else if (title.includes('launch action') || title.includes('/launch')) {
    whatWasExamined = 'The PDF object catalog was inspected for operating system execution directives.';
    whatWasFound = 'Found /Launch action designed to execute external applications, command prompts, or scripts.';
    whyItMatters = 'Launch actions are high-severity attack vectors used to trigger malicious binaries outside the PDF viewer.';
    whatToDoNext = 'Quarantine the file immediately. Do not permit application launching from PDF viewer software.';
    engineName = 'PDF Exploit Screener (pdf.py)';
    detectionMethod = 'Byte-level token scan for /Launch directives and associated target arguments';
    confidenceLabel = 'High-Risk Exploit Pattern';
    limitations = 'Identifies execution directive; external payload availability depends on target workstation environment.';
  }

  // 8. PDF Microscopic Text
  else if (title.includes('microscopic') || title.includes('< 2.0 pt')) {
    whatWasExamined = 'Document text render blocks and font metrics were analyzed per page.';
    whatWasFound = 'Rendered text with font size under 2.0 points was detected in the document.';
    whyItMatters = 'Microscopic text is invisible to human readers and often conceals search-engine keywords, hidden contract terms, or prompt injection.';
    whatToDoNext = 'Inspect the microscopic text spans using text extraction or zoom tools to review the concealed text.';
    engineName = 'PDF Microscopic Text Analyzer (pdf.py)';
    detectionMethod = 'PyMuPDF text dict span size inspection (< 2.0 pt with length > 1)';
    confidenceLabel = 'Geometric Typography Check';
    limitations = 'Fine print, registration marks, or vector alignment artifacts can occasionally register small font sizes.';
  }

  // 9. Office Remote Template Injection
  else if (title.includes('template') || title.includes('external')) {
    whatWasExamined = 'The external document relationships and template paths (_rels) were evaluated.';
    whatWasFound = 'This document is configured to contact an external remote server to fetch its formatting template.';
    whyItMatters = 'Remote template injection is a technique where benign-looking Word documents download malicious macro payloads when opened.';
    whatToDoNext = 'Do not open the document with internet access enabled. Inspect the target URI in the technical evidence drawer.';
    engineName = 'Office OpenXML Analyzer (office.py)';
    detectionMethod = 'TargetMode="External" attribute parsing within word/_rels/settings.xml.rels';
    confidenceLabel = 'OpenXML Relationship Target Verification';
    limitations = 'Cannot verify if the remote server is currently live without outbound requests (blocked for privacy).';
  }

  // 10. Cloaked Macros & VBA
  else if (title.includes('macro') || title.includes('vba')) {
    whatWasExamined = 'The document archive was checked for Visual Basic for Applications (VBA) macro containers.';
    whatWasFound = 'A hidden or cloaked VBA macro project (vbaProject.bin) was detected inside this document.';
    whyItMatters = 'Macros can execute arbitrary system commands, download ransomware, or steal local credentials when enabled.';
    whatToDoNext = 'Never enable macros for this document. Inspect the binary storage stream in an isolated environment.';
    engineName = 'Office VBA Macro Screener (office.py)';
    detectionMethod = 'Binary package directory inspection for vbaProject.bin and oleObject*.bin via oletools';
    confidenceLabel = 'VBA Container & Heuristic Verification';
    limitations = 'Detects macro existence; does not decompile proprietary P-code without external sandboxes.';
  }

  // 11. Hidden Sheets / Slides
  else if (title.includes('hidden sheet') || title.includes('hidden slide')) {
    whatWasExamined = 'Document sheets and presentation slide visibility flags were inspected.';
    whatWasFound = 'One or more worksheets or slides are marked as hidden or veryHidden in the document configuration.';
    whyItMatters = 'Hidden sheets can conceal sensitive financial data, internal notes, or proprietary formula parameters.';
    whatToDoNext = 'Inspect the unhidden sheet content in spreadsheet software or review the sheet references.';
    engineName = 'Office OpenXML Structure Parser (office.py)';
    detectionMethod = 'XML state attribute parsing (state="veryHidden" or state="hidden") in workbook.xml';
    confidenceLabel = 'XML Configuration Flag Inspection';
    limitations = 'Identifies visibility state; does not evaluate the confidentiality of the hidden text.';
  }

  // 12. Appended Trailing Bytes (Steganography)
  else if (title.includes('appended data') || title.includes('trailing bytes') || title.includes('steganography')) {
    whatWasExamined = 'File byte stream was inspected for data appended beyond the official file termination marker.';
    whatWasFound = 'Trailing binary data was detected past the JPEG EOI (FF D9) or PNG IEND chunk.';
    whyItMatters = 'Data appended after the end marker is invisible to image viewers but can contain embedded archives, polyglot payloads, or encrypted files.';
    whatToDoNext = 'Extract the trailing byte stream and inspect its magic bytes to determine what is hidden.';
    engineName = 'Image Structure & Steganography Screener (image.py)';
    detectionMethod = 'Binary scan identifying data past format termination markers (JPEG EOI / PNG IEND)';
    confidenceLabel = 'Deterministic Byte Offset Boundary Check';
    limitations = 'Detects payload presence; does not decrypt proprietary encrypted data.';
  }

  // 13. EXIF Graphic Editing Software Signature
  else if (title.includes('editing software') || title.includes('graphic design') || title.includes('producer')) {
    whatWasExamined = 'Image EXIF tags and document producer metadata were screened for graphic editor signatures.';
    whatWasFound = 'Metadata indicates the file was created or re-saved using graphic editing software (Photoshop, Canva, GIMP, etc.).';
    whyItMatters = 'Official certificates, bank statements, and identity documents are produced by enterprise reporting systems, not image editors.';
    whatToDoNext = 'Examine visual boundaries and text alignments for evidence of manual editing or tampering.';
    engineName = 'Metadata Software Screener (image.py / pdf.py)';
    detectionMethod = 'Case-insensitive keyword matching against curated editing tool list';
    confidenceLabel = 'Metadata Tag String Verification';
    limitations = 'Benign scans are sometimes converted or rotated in graphic tools; presence alone is not definitive proof of fraud.';
  }

  // 14. Machine Learning Tamper Prediction
  else if (title.includes('machine learning') || title.includes('efficientnet')) {
    whatWasExamined = 'Image spatial frequencies and pixel patterns were evaluated using a convolutional neural network.';
    whatWasFound = rawDetail || 'The AI model detected patterns statistically consistent with digital image manipulation.';
    whyItMatters = 'The image may contain spliced sections from another photo, copy-move cloning, or localized erasing.';
    whatToDoNext = 'Inspect the Grad-CAM heatmap overlay to see which regions triggered the AI prediction. Cross-verify with EXIF metadata.';
    engineName = 'EfficientNet-B0 Tamper Classifier (image.py)';
    detectionMethod = 'PyTorch convolutional neural inference fine-tuned on CASIA 2.0 dataset';
    confidenceLabel = 'Statistical Model Probability (CASIA 2.0 Benchmark)';
    limitations = 'The EfficientNet-B0 prototype model has an empirical test accuracy of approx 71.37%. AI predictions represent statistical anomaly likelihood, NOT definitive forensic proof of manipulation.';
  }

  // 15. ELA Anomaly
  else if (title.includes('error level') || title.includes('ela')) {
    whatWasExamined = 'JPEG compression error levels were analyzed across the entire image.';
    whatWasFound = 'Significant differences in compression error variance were detected between image sections.';
    whyItMatters = 'When an object from one image is pasted into another, its compression history differs from the background, causing it to stand out.';
    whatToDoNext = 'Inspect the ELA differential visualization to identify localized clusters of high error variance.';
    engineName = 'Error Level Analysis Engine (image.py)';
    detectionMethod = 'Resaved at 95% JPEG quality factor; absolute Euclidean pixel distance matrix computed';
    confidenceLabel = 'Quantitative Compression Differential';
    limitations = 'ELA differences naturally occur along high-contrast boundaries and resaved JPEG generations; they do not by themselves prove malicious intent.';
  }

  // 16. Zip Slip / Zip Bomb
  else if (title.includes('zip slip') || title.includes('bomb') || title.includes('traversal')) {
    whatWasExamined = 'Archive member paths and uncompressed size ratios were screened before extraction.';
    whatWasFound = 'The ZIP archive contains file paths attempting directory traversal (e.g. ../../) or an extreme compression ratio.';
    whyItMatters = 'Zip Slip attacks overwrite system files during extraction; Zip Bombs consume gigabytes of memory to crash the workstation.';
    whatToDoNext = 'Do not extract this archive on your host machine. PRAMAANX blocked extraction automatically.';
    engineName = 'ZIP Hardened Sandbox Validator (common.py)';
    detectionMethod = 'Canonical path verification against target sandbox root directory and compression ratio auditing';
    confidenceLabel = 'Pre-Extraction Security Audit';
    limitations = 'Pre-extraction screening neutralizes structural attacks; payload files still require independent analysis.';
  }

  return {
    whatWasExamined,
    whatWasFound,
    whyItMatters,
    whatToDoNext,
    engineName,
    detectionMethod,
    confidenceLabel,
    limitations,
    taxonomy,
    traceabilityItems,
    whatWasObserved: whatWasFound,
    detectingAnalyzer: engineName,
    recommendedNextStep: whatToDoNext,
    exactEvidence: finding.evidence || {},
  };
}

/**
 * Computes the exact explainable percentage contribution of each finding to the total Noisy-OR risk score.
 */
export function calculateExplainableContributions(findings, totalScore) {
  if (!findings || findings.length === 0 || totalScore === 0) {
    return [];
  }

  const validFindings = findings.filter((f) => f.weight && f.weight > 0);
  if (validFindings.length === 0) {
    return [];
  }

  // Calculate -ln(1 - w) for each finding (independent log-evidence)
  const logWeights = validFindings.map((f) => {
    const w = Math.min(0.999, Math.max(0.01, Number(f.weight) || 0.1));
    return -Math.log(1.0 - w);
  });

  const sumLogWeights = logWeights.reduce((acc, val) => acc + val, 0);

  return validFindings.map((f, idx) => {
    const proportion = sumLogWeights > 0 ? logWeights[idx] / sumLogWeights : 1 / validFindings.length;
    const contributionPoints = Math.round(proportion * totalScore * 10) / 10;
    return {
      title: f.title || f.name || 'Finding',
      severity: f.severity || 'low',
      weight: Number(f.weight),
      contributionPoints,
      contributionPercentage: Math.round(proportion * 100),
    };
  });
}

/**
 * Generates an isolated, beginner-friendly AI Tamper Assessment based on documented thresholds.
 * Strictly separates AI predictions from the deterministic structural risk score.
 */
export function getAiAssessment(findings = [], analysis = {}, fileType = '') {
  const normType = String(fileType || '').toLowerCase();
  const isImage =
    normType.includes('image') ||
    normType.includes('jpg') ||
    normType.includes('jpeg') ||
    normType.includes('png') ||
    normType.includes('bmp') ||
    normType.includes('tiff');

  // Check explicit ai_status from backend
  if (analysis?.ai_status === 'unavailable') {
    return {
      executed: false,
      available: false,
      level: 'unavailable',
      label: 'AI screening unavailable',
      headline: 'AI Screening Unavailable',
      badgeVariant: 'neutral',
      scoreText: 'Unavailable',
      percentage: null,
      probability: null,
      explanation:
        'AI screening unavailable for this file. Deterministic container, entropy, and metadata checks remain fully active.',
      disclaimer:
        'Absence of neural screening reduces edit-detection sensitivity. Specimen is evaluated with limited evidence.',
    };
  }

  // Search for ML finding
  const mlFinding = findings.find((f) => {
    const t = (f.title || f.name || '').toLowerCase();
    const d = (f.detail || f.description || '').toLowerCase();
    return (
      t.includes('efficientnet') ||
      t.includes('neural') ||
      t.includes('machine learning') ||
      t.includes('tamper probability') ||
      d.includes('efficientnet') ||
      f.category === 'machine_learning'
    );
  });

  if (mlFinding?.evidence?.ai_status === 'unavailable') {
    return {
      executed: false,
      available: false,
      level: 'unavailable',
      label: 'AI screening unavailable',
      headline: 'AI Screening Unavailable',
      badgeVariant: 'neutral',
      scoreText: 'Unavailable',
      percentage: null,
      probability: null,
      explanation:
        'AI screening unavailable for this file. Deterministic container, entropy, and metadata checks remain fully active.',
      disclaimer:
        'Absence of neural screening reduces edit-detection sensitivity. Specimen is evaluated with limited evidence.',
    };
  }

  let prob = null;
  if (mlFinding?.evidence?.tampered_probability !== undefined) {
    prob = Number(mlFinding.evidence.tampered_probability);
  } else if (mlFinding?.evidence?.tamper_probability !== undefined) {
    prob = Number(mlFinding.evidence.tamper_probability);
  } else if (mlFinding?.evidence?.confidence !== undefined) {
    prob = Number(mlFinding.evidence.confidence);
  } else if (mlFinding?.model_confidence !== undefined) {
    prob = Number(mlFinding.model_confidence);
  } else if (analysis?.visual_evidence?.gradcam_url || analysis?.visual_evidence?.ela_url) {
    const match =
      mlFinding?.detail?.match(/probability\s*\(?([0-9.]+)\)?/i) ||
      mlFinding?.description?.match(/probability\s*\(?([0-9.]+)\)?/i);
    if (match) {
      prob = parseFloat(match[1]);
    }
  }

  // Case 1: Non-image format where ML is not applicable
  if (!isImage) {
    return {
      executed: false,
      available: false,
      isProvisional: true,
      validationMilestone: 'Milestone G',
      provisionalNotice:
        'Provisional Heuristic Thresholds (Pending Milestone G Validation): Neural classification boundaries are working estimates subject to empirical ROC validation in Milestone G.',
      level: 'not_applicable',
      label: 'Not Applicable',
      headline: 'Rule-Based Inspection Applied',
      badgeVariant: 'neutral',
      explanation:
        'Spatial neural tamper classification is specifically designed for raster image pixels (JPEG, PNG, BMP). This document was screened with deterministic structural, entropy, and relationship parsers.',
      disclaimer:
        'Structural and format parsing rules provide definitive verification of container trees, scripts, and revision histories.',
      probability: null,
      scoreText: 'N/A',
      percentage: null,
    };
  }

  // Case 2: Invalid, NaN, or infinite probability
  if (prob === null || Number.isNaN(prob) || !Number.isFinite(prob) || prob < 0 || prob > 1) {
    return {
      executed: false,
      available: false,
      isProvisional: true,
      validationMilestone: 'Milestone G',
      provisionalNotice:
        'Provisional Heuristic Notice (Pending Milestone G Validation): AI screening unavailable due to non-finite inference values.',
      level: 'unavailable',
      label: 'AI screening unavailable',
      headline: 'AI Screening Unavailable',
      badgeVariant: 'neutral',
      scoreText: 'Unavailable',
      percentage: null,
      probability: null,
      explanation:
        'AI screening unavailable: model produced non-finite or uncalibrated outputs.',
      disclaimer:
        'Absence of neural inference reduces edit-detection sensitivity. Specimen is evaluated with limited evidence.',
    };
  }

  const percentage = Math.round(prob * 100);

  const isCalibrated = analysis?.ml_prediction?.is_calibrated === true;

  // Case 3: Low likelihood (< 0.35)
  if (prob < ML_THRESHOLDS.LOW_MAX) {
    return {
      executed: true,
      available: true,
      isProvisional: true,
      validationMilestone: 'Milestone G',
      provisionalNotice: isCalibrated
        ? 'Calibrated model (Target FPR < 5.0%, Validated in Milestone G). Calibrated threshold boundary (< 35%).'
        : 'Experimental model (Uncalibrated, Pending Milestone G Validation). Provisional heuristic boundary (< 35%).',
      level: 'low',
      label: 'Low Tamper Likelihood',
      headline: 'No Obvious Splicing Patterns Detected',
      badgeVariant: 'low',
      scoreText: `${percentage}%`,
      percentage,
      probability: prob,
      explanation: `The model recorded a low tamper probability of ${percentage}%. Spatial frequencies and pixel distributions remain consistent across the image frame.`,
      disclaimer:
        'Scientific boundary: A low score does not guarantee authenticity. It means convolutional features of splicing were not identified by the model. Global edits or modifications outside the training distribution cannot be ruled out.',
    };
  }

  // Case 4: Inconclusive / Uncertain prediction (0.35 - 0.65)
  if (prob <= ML_THRESHOLDS.UNCERTAIN_MAX) {
    return {
      executed: true,
      available: true,
      isProvisional: true,
      validationMilestone: 'Milestone G',
      provisionalNotice: isCalibrated
        ? 'Calibrated model (Validated in Milestone G). The calibrated uncertainty zone (35%–65%) represents unconfirmed patterns.'
        : 'Experimental model (Uncalibrated, Pending Milestone G Validation). The provisional uncertainty zone (35%–65%) represents unconfirmed patterns.',
      level: 'inconclusive',
      label: 'Inconclusive / Uncertain',
      headline: 'AI Assessment is Inconclusive',
      badgeVariant: 'medium',
      scoreText: `${percentage}%`,
      percentage,
      probability: prob,
      explanation: `The model prediction (${percentage}%) falls within the ${isCalibrated ? 'calibrated' : 'provisional'} range of uncertainty (${Math.round(ML_THRESHOLDS.LOW_MAX * 100)}%–${Math.round(ML_THRESHOLDS.UNCERTAIN_MAX * 100)}%). Sensor noise, re-compression, or subtle contrast boundaries prevent a definitive classification.`,
      disclaimer:
        'Investigation guidance: Do not treat this result as evidence of either tampering or authenticity. Cross-verify with JPEG structure, metadata, and Error Level Analysis (ELA).',
    };
  }

  // Case 5: Elevated tamper likelihood (> 0.65)
  return {
    executed: true,
    available: true,
    isProvisional: true,
    validationMilestone: 'Milestone G',
    provisionalNotice: isCalibrated
      ? 'Calibrated model (Target FPR < 5.0%, Validated in Milestone G). Calibrated elevated threshold (> 65%).'
      : 'Experimental model (Uncalibrated, Pending Milestone G Validation). Provisional elevated threshold (> 65%).',
    level: 'elevated',
    label: 'Elevated Tamper Likelihood',
    headline: 'AI Detected Splicing or Editing Patterns',
    badgeVariant: 'high',
    scoreText: `${percentage}%`,
    percentage,
    probability: prob,
    explanation: `The model recorded an elevated tamper probability of ${percentage}%. Neural activation patterns indicate pixel discontinuities consistent with localized splicing or copy-move forgery.`,
    disclaimer:
      'Investigation guidance: Review the Grad-CAM heatmap below to inspect the highlighted spatial regions swaying the neural classifier.',
  };
}

/**
 * Evaluates whether an individual analyzer check was:
 * - Passed: executed without anomalies
 * - Flagged: executed and recorded suspicious indicators
 * - Not performed: intentionally skipped / not applicable to format sub-type
 * - Error: encountered an unhandled exception or parsing failure
 */
export function evaluateExecutionStatus(matchingFindings = [], isSkipped = false, skipReason = '') {
  if (isSkipped) {
    return {
      status: 'Not performed',
      statusVariant: 'not_performed',
      badgeText: 'Not performed',
      detail: skipReason || 'Check was not performed for this file configuration.',
    };
  }

  if (!matchingFindings || matchingFindings.length === 0) {
    return {
      status: 'Passed',
      statusVariant: 'passed',
      badgeText: 'Passed',
      detail: 'Analyzer executed successfully; no anomalies detected.',
    };
  }

  const hasError = matchingFindings.some((f) => {
    const t = (f.title || f.name || '').toLowerCase();
    const d = (f.detail || f.description || '').toLowerCase();
    return (
      f.category === 'inconclusive' ||
      t.includes('error') ||
      t.includes('corrupted') ||
      t.includes('failed') ||
      d.includes('failed to parse') ||
      d.includes('unhandled exception') ||
      d.includes('truncated')
    );
  });

  if (hasError) {
    return {
      status: 'Error',
      statusVariant: 'error',
      badgeText: 'Error',
      detail: 'Analyzer encountered a parsing or structure execution error.',
    };
  }

  return {
    status: 'Flagged',
    statusVariant: 'flagged',
    badgeText: 'Flagged',
    detail: `${matchingFindings.length} indicator(s) flagged during inspection.`,
  };
}

/**
 * Builds a file-specific checklist showing only the checks that were genuinely performed for this file format.
 * Returns checklist items with exact execution statuses: 'Passed', 'Flagged', 'Not performed', or 'Error'.
 */
export function getFileSpecificChecklist(fileType, detectedMime, findings = []) {
  const normType = String(fileType || '').toLowerCase();
  const normMime = String(detectedMime || '').toLowerCase();

  const isPdf = normType.includes('pdf') || normMime.includes('pdf');
  const isDocx = normType.includes('docx') || normMime.includes('wordprocessingml');
  const isXlsx = normType.includes('xlsx') || normMime.includes('spreadsheetml');
  const isPptx = normType.includes('pptx') || normMime.includes('presentationml');
  const isOffice =
    isDocx ||
    isXlsx ||
    isPptx ||
    normType.includes('office') ||
    normMime.includes('officedocument');
  const isZip = normType.includes('zip') || normMime.includes('zip') || normType.includes('archive');
  const isJpeg = normType.includes('jpg') || normType.includes('jpeg') || normMime.includes('jpeg');

  const checklist = [];

  const findMatching = (keywords) => {
    return findings.filter((f) => {
      const text = `${f.title || f.name || ''} ${f.detail || f.description || ''}`.toLowerCase();
      return keywords.some((k) => text.includes(k.toLowerCase()));
    });
  };

  if (isPdf) {
    const headerMatch = findMatching(['magic', 'signature', 'spoof', 'mismatch', 'preamble']);
    const headerEval = evaluateExecutionStatus(headerMatch);
    checklist.push({
      id: 'pdf_header',
      name: 'Format Signature & Header',
      description: 'Checks for valid %PDF- magic bytes and extension consistency',
      status: headerEval.status,
      statusVariant: headerEval.statusVariant,
      detail: headerEval.detail,
      severity: headerMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: headerMatch,
    });

    const revisionMatch = findMatching(['revision', '%%eof', 'trailer', 'xref']);
    const revisionEval = evaluateExecutionStatus(revisionMatch);
    checklist.push({
      id: 'pdf_revisions',
      name: 'Revision History (%%EOF)',
      description: 'Screens for multiple trailer markers and post-signature alterations',
      status: revisionEval.status,
      statusVariant: revisionEval.statusVariant,
      detail: revisionEval.detail,
      severity: revisionMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: revisionMatch,
    });

    const scriptMatch = findMatching(['javascript', '/js', 'script', '/openaction', '/aa']);
    const scriptEval = evaluateExecutionStatus(scriptMatch);
    checklist.push({
      id: 'pdf_scripts',
      name: 'Active Code & JavaScript',
      description: 'Inspects dictionary tree for auto-executing scripts or dynamic actions',
      status: scriptEval.status,
      statusVariant: scriptEval.statusVariant,
      detail: scriptEval.detail,
      severity: scriptMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: scriptMatch,
    });

    const launchMatch = findMatching([
      '/launch',
      'launch action',
      'command',
      'executable',
      'suspicious uri',
      'ip address',
    ]);
    const launchEval = evaluateExecutionStatus(launchMatch);
    checklist.push({
      id: 'pdf_launch',
      name: 'Launch Directives & External URIs',
      description: 'Detects OS command execution directives and suspicious IP endpoints',
      status: launchEval.status,
      statusVariant: launchEval.statusVariant,
      detail: launchEval.detail,
      severity: launchMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: launchMatch,
    });

    const fontMatch = findMatching(['microscopic', 'font', 'hidden text', 'embedded file']);
    const fontEval = evaluateExecutionStatus(fontMatch);
    checklist.push({
      id: 'pdf_typography',
      name: 'Typography & Microscopic Text',
      description: 'Screens for invisible text (< 2.0 pt) and embedded file attachments',
      status: fontEval.status,
      statusVariant: fontEval.statusVariant,
      detail: fontEval.detail,
      severity: fontMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: fontMatch,
    });

    const metaMatch = findMatching(['inverted', 'chronology', 'timestamp', 'date', 'producer']);
    const metaEval = evaluateExecutionStatus(metaMatch);
    checklist.push({
      id: 'pdf_metadata',
      name: 'Metadata Chronology',
      description: 'Verifies CreationDate and ModDate chronological order and consistency',
      status: metaEval.status,
      statusVariant: metaEval.statusVariant,
      detail: metaEval.detail,
      severity: metaMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: metaMatch,
    });
  } else if (isOffice) {
    const pkgMatch = findMatching(['opc', 'package', 'container', 'magic', 'spoof', 'mismatch']);
    const pkgEval = evaluateExecutionStatus(pkgMatch);
    checklist.push({
      id: 'office_pkg',
      name: 'OpenXML Package Structure',
      description: 'Verifies OPC relationship graphs and valid ZIP XML parts',
      status: pkgEval.status,
      statusVariant: pkgEval.statusVariant,
      detail: pkgEval.detail,
      severity: pkgMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: pkgMatch,
    });

    const macroMatch = findMatching(['macro', 'vba', 'vbaproject', 'ole']);
    const macroEval = evaluateExecutionStatus(macroMatch);
    checklist.push({
      id: 'office_macros',
      name: 'Macros & Embedded VBA',
      description: 'Inspects document parts for hidden macro projects or OLE objects',
      status: macroEval.status,
      statusVariant: macroEval.statusVariant,
      detail: macroEval.detail,
      severity: macroMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: macroMatch,
    });

    const relsMatch = findMatching(['template', 'remote', 'unc', 'external', 'target']);
    const relsEval = evaluateExecutionStatus(relsMatch);
    checklist.push({
      id: 'office_template',
      name: 'External Templates & Targets',
      description: 'Detects remote template injection and outbound UNC path references',
      status: relsEval.status,
      statusVariant: relsEval.statusVariant,
      detail: relsEval.detail,
      severity: relsMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: relsMatch,
    });

    // Concealed sheets/slides is performed for XLSX/PPTX; for pure DOCX, mark "Not performed"
    const skipHidden = isDocx && !isXlsx && !isPptx;
    const hiddenMatch = findMatching(['hidden sheet', 'veryhidden', 'hidden slide', 'sheet', 'slide']);
    const hiddenEval = evaluateExecutionStatus(
      hiddenMatch,
      skipHidden,
      'Not performed: Sheet and slide concealment checks apply to Excel & PowerPoint.'
    );
    checklist.push({
      id: 'office_hidden',
      name: 'Concealed Sheets & Slides',
      description: 'Identifies veryHidden Excel sheets and concealed PowerPoint slides',
      status: hiddenEval.status,
      statusVariant: hiddenEval.statusVariant,
      detail: hiddenEval.detail,
      severity: hiddenMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: hiddenMatch,
    });

    // Vanished text is performed for DOCX; for XLSX/PPTX, mark "Not performed"
    const skipText = (isXlsx || isPptx) && !isDocx;
    const textMatch = findMatching(['vanished', 'white-on-white', 'color', 'hidden text']);
    const textEval = evaluateExecutionStatus(
      textMatch,
      skipText,
      'Not performed: Word-level font contrast inspection applies to Word documents.'
    );
    checklist.push({
      id: 'office_text',
      name: 'Vanished White-on-White Text',
      description: 'Scans for text formatted identically to background color to conceal words',
      status: textEval.status,
      statusVariant: textEval.statusVariant,
      detail: textEval.detail,
      severity: textMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: textMatch,
    });

    const metaMatch = findMatching(['inverted', 'author', 'modified', 'chronology', 'timestamp']);
    const metaEval = evaluateExecutionStatus(metaMatch);
    checklist.push({
      id: 'office_meta',
      name: 'Author Metadata & Timestamps',
      description: 'Audits creator tags, revision counts, and chronological integrity',
      status: metaEval.status,
      statusVariant: metaEval.statusVariant,
      detail: metaEval.detail,
      severity: metaMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: metaMatch,
    });
  } else if (isZip) {
    const structMatch = findMatching(['pkware', 'header', 'central directory', 'corrupt']);
    const structEval = evaluateExecutionStatus(structMatch);
    checklist.push({
      id: 'zip_struct',
      name: 'Archive Header & Container',
      description: 'Validates PKWare header magic bytes and central directory record',
      status: structEval.status,
      statusVariant: structEval.statusVariant,
      detail: structEval.detail,
      severity: structMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: structMatch,
    });

    const slipMatch = findMatching(['zip slip', 'traversal', 'path traversal', '..', 'dot-dot']);
    const slipEval = evaluateExecutionStatus(slipMatch);
    checklist.push({
      id: 'zip_slip',
      name: 'Directory Traversal (Zip Slip)',
      description: 'Screens extracted member paths to prevent host file overwrite attacks',
      status: slipEval.status,
      statusVariant: slipEval.statusVariant,
      detail: slipEval.detail,
      severity: slipMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: slipMatch,
    });

    const bombMatch = findMatching([
      'bomb',
      'compression ratio',
      'uncompressed',
      'flood',
      'entry count',
    ]);
    const bombEval = evaluateExecutionStatus(bombMatch);
    checklist.push({
      id: 'zip_bomb',
      name: 'Decompression & Bomb Safety',
      description: 'Audits compression ratios and maximum uncompressed size limits',
      status: bombEval.status,
      statusVariant: bombEval.statusVariant,
      detail: bombEval.detail,
      severity: bombMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: bombMatch,
    });

    const memMatch = findMatching(['executable', 'dangerous', 'script', '.exe', '.bat', '.sh']);
    const memEval = evaluateExecutionStatus(memMatch);
    checklist.push({
      id: 'zip_members',
      name: 'Extracted Member Screening',
      description: 'Inspects contained filenames for cloaked or dangerous executable scripts',
      status: memEval.status,
      statusVariant: memEval.statusVariant,
      detail: memEval.detail,
      severity: memMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: memMatch,
    });
  } else {
    // Default to Image checklist (JPEG, PNG, BMP, TIFF)
    const headerMatch = findMatching(['magic', 'signature', 'header', 'spoof', 'mismatch']);
    const headerEval = evaluateExecutionStatus(headerMatch);
    checklist.push({
      id: 'img_header',
      name: 'Magic Byte Header Integrity',
      description: 'Confirms valid image signature (e.g. JPEG SOI FF D8 / PNG \\x89PNG / BMP BM)',
      status: headerEval.status,
      statusVariant: headerEval.statusVariant,
      detail: headerEval.detail,
      severity: headerMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: headerMatch,
    });

    const entropyMatch = findMatching([
      'entropy',
      'appended',
      'trailing',
      'steganography',
      'eoi',
      'iend',
    ]);
    const entropyEval = evaluateExecutionStatus(entropyMatch);
    checklist.push({
      id: 'img_entropy',
      name: 'Byte Distribution & Trailing Data',
      description: 'Measures Shannon entropy and inspects for hidden data appended past end-markers',
      status: entropyEval.status,
      statusVariant: entropyEval.statusVariant,
      detail: entropyEval.detail,
      severity: entropyMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: entropyMatch,
    });

    const exifMatch = findMatching([
      'software',
      'photoshop',
      'canva',
      'gimp',
      'editor',
      'producer',
      'exif',
    ]);
    const exifEval = evaluateExecutionStatus(exifMatch);
    checklist.push({
      id: 'img_exif',
      name: 'EXIF Metadata & Editor Signatures',
      description: 'Identifies software signatures from graphic design tools (Photoshop, Canva, GIMP)',
      status: exifEval.status,
      statusVariant: exifEval.statusVariant,
      detail: exifEval.detail,
      severity: exifMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: exifMatch,
    });

    // ELA is only applicable to lossy compression (JPEG)
    const isLossless = !isJpeg;
    const elaMatch = findMatching(['error level', 'ela', 'compression', 'differential']);
    const elaEval = evaluateExecutionStatus(
      elaMatch,
      isLossless,
      'Not performed: ELA evaluates lossy JPEG DCT quantization matrices.'
    );
    checklist.push({
      id: 'img_ela',
      name: 'Error Level Analysis (ELA)',
      description: 'Calculates JPEG re-compression error differentials to reveal spliced regions',
      status: elaEval.status,
      statusVariant: elaEval.statusVariant,
      detail: elaEval.detail,
      severity: elaMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: elaMatch,
    });

    const aiMatch = findMatching([
      'efficientnet',
      'neural',
      'machine learning',
      'tamper probability',
      'grad-cam',
    ]);
    const aiEval = evaluateExecutionStatus(aiMatch);
    checklist.push({
      id: 'img_ai',
      name: 'AI Neural Tamper Screening',
      description: 'Evaluates convolutional spatial features using the CASIA 2.0-trained EfficientNet-B0 model',
      status: aiEval.status,
      statusVariant: aiEval.statusVariant,
      detail: aiEval.detail,
      severity: aiMatch.some((f) => f.severity === 'high') ? 'high' : 'medium',
      findings: aiMatch,
    });
  }

  return checklist;
}

/**
 * Builds a clear, 10-second plain-English overall verdict using the 4-state system:
 * - `no_signs`
 * - `limited_evidence`
 * - `review_recommended`
 * - `high_risk`
 *
 * Rules: Never uses the words "authentic", "unaltered", "real", or "fake".
 */
export function getPlainEnglishVerdict(riskScore, _riskCategory, findings = [], fileType = '', analysis = {}) {
  // If backend provided an explicit verdict, honor it directly
  const explicitVerdict = analysis?.verdict;

  // Determine if limited evidence applies (Task 2)
  const isImage = String(fileType || '').toLowerCase().match(/jpg|jpeg|png|bmp|image/);
  const isAiUnavailable = analysis?.ai_status === 'unavailable';
  const absentMetaCount = analysis?.metadata?.absent_fields_count ?? 0;
  const isLowQuality = analysis?.jpeg_structure?.estimated_quality !== undefined && analysis.jpeg_structure.estimated_quality !== null && analysis.jpeg_structure.estimated_quality < 80;
  const isMessagingRes = analysis?.jpeg_structure?.recompression_indicators?.messaging_resolution_limit === true;
  const isDoubleCompression = analysis?.jpeg_structure?.double_compression_suspected === true;

  const hasLimitedEvidenceConditions = isImage && (
    isAiUnavailable ||
    absentMetaCount >= 5 ||
    isLowQuality ||
    isMessagingRes ||
    isDoubleCompression
  );

  const hasHighFindings = findings.some((f) => (f.severity || '').toLowerCase() === 'high' && f.category !== 'inconclusive');
  const hasMedFindings = findings.some((f) => (f.severity || '').toLowerCase() === 'medium' && f.category !== 'inconclusive');

  let state;
  if (explicitVerdict) {
    state = explicitVerdict;
  } else if (riskScore > 60 || hasHighFindings) {
    state = 'high_risk';
  } else if (riskScore > 30 || hasMedFindings) {
    state = 'review_recommended';
  } else if (hasLimitedEvidenceConditions) {
    state = 'limited_evidence';
  } else {
    state = 'no_signs';
  }

  if (state === 'high_risk') {
    return {
      status: 'danger',
      verdictKey: 'high_risk',
      badgeLabel: 'HIGH RISK OF EDITING',
      badgeVariant: 'high',
      headline: 'Critical Risk: High Risk of Editing Detected',
      subheadline: 'Strong indicators of manipulation or structural tampering were identified.',
      summary: 'High risk of editing detected. Strong indicators of manipulation or structural tampering were identified.',
      nextSteps: [
        'Do not treat this file as an unmodified original.',
        'Quarantine the specimen and inspect the detailed byte offsets and heatmap regions in Technical View.',
      ],
    };
  }

  if (state === 'review_recommended') {
    return {
      status: 'caution',
      verdictKey: 'review_recommended',
      badgeLabel: 'REVIEW RECOMMENDED',
      badgeVariant: 'medium',
      headline: 'Review Advised: Review Recommended',
      subheadline: 'Anomalies were detected that warrant manual verification.',
      summary: 'Review recommended. Anomalies were detected that warrant manual verification.',
      nextSteps: [
        'Inspect the flagged findings below to see which sections of the file were modified.',
        'Review the visual evidence and metadata tabs for localized anomalies.',
      ],
    };
  }

  if (state === 'limited_evidence') {
    return {
      status: 'limited_evidence',
      verdictKey: 'limited_evidence',
      badgeLabel: 'LIMITED EVIDENCE',
      badgeVariant: 'medium',
      headline: 'Limited Evidence',
      subheadline: 'Image was likely shared through a messaging app or recompressed.',
      summary: 'Limited evidence. This image was likely shared through a messaging app or recompressed, so edit-detection checks are less reliable. We cannot confirm it is authentic or edited.',
      nextSteps: [
        'Limited evidence note: Recompression, resized dimensions, or stripped metadata is typical of messaging platforms and does NOT constitute evidence of manipulation or editing.',
        'Request the original uncompressed camera capture directly from the source if conclusive forensic verification is required.',
        'Inspect the JPEG structure panel in the Metadata tab for quantization artifacts and compression traces.',
      ],
    };
  }

  // no_signs: allowed ONLY when none of the limited-evidence conditions are true and every check passed
  return {
    status: 'safe',
    verdictKey: 'no_signs',
    badgeLabel: 'NO SIGNS OF EDITING',
    badgeVariant: 'low',
    headline: 'No Signs of Localized Editing Detected (Structure Appears Normal)',
    subheadline: 'All primary structural, metadata, and compression checks passed without anomalies.',
    summary: 'No signs of localized editing detected.',
    nextSteps: [
      'Standard handling applies. No localized splicing or copy-move artifacts were detected.',
      'Global edits such as color filters or brightness adjustments cannot be reliably detected.',
    ],
  };
}
