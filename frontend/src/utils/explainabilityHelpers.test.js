/**
 * PRAMAANX - Unit Tests for Forensic Explainability Helpers (Refined UX)
 * Tests ML provisional threshold boundaries, inconclusive predictions,
 * format-specific checklist execution statuses (Passed, Flagged, Not performed, Error),
 * and plain-English verdicts.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ML_THRESHOLDS,
  getAiAssessment,
  getFileSpecificChecklist,
  evaluateExecutionStatus,
  getPlainEnglishVerdict,
  calculateExplainableContributions,
  classifyFindingTaxonomy,
} from './explainabilityHelpers.js';

test('ML Thresholds are provisional pending Milestone G validation', () => {
  assert.equal(ML_THRESHOLDS.LOW_MAX, 0.35);
  assert.equal(ML_THRESHOLDS.UNCERTAIN_MAX, 0.65);
  assert.equal(ML_THRESHOLDS.HIGH_MIN, 0.65);
  assert.equal(ML_THRESHOLDS.IS_PROVISIONAL, true);
  assert.equal(ML_THRESHOLDS.VALIDATION_MILESTONE, 'Milestone G');
  assert.match(ML_THRESHOLDS.PROVISIONAL_NOTICE, /Milestone G/i);
});

test('getAiAssessment correctly identifies low tamper likelihood (< 0.35) with provisional notice', () => {
  const findings = [
    {
      title: 'EfficientNet-B0 Tamper Screening',
      evidence: { tamper_probability: 0.18 },
    },
  ];
  const assessment = getAiAssessment(findings, {}, 'image');

  assert.equal(assessment.executed, true);
  assert.equal(assessment.isProvisional, true);
  assert.equal(assessment.level, 'low');
  assert.equal(assessment.badgeVariant, 'low');
  assert.equal(assessment.scoreText, '18%');
  assert.match(assessment.explanation, /low tamper probability of 18%/i);
  assert.match(assessment.provisionalNotice, /Milestone G/i);
  assert.match(assessment.disclaimer, /does not guarantee authenticity/i);
});

test('getAiAssessment correctly classifies uncertain / inconclusive predictions (0.35 - 0.65)', () => {
  const findings = [
    {
      title: 'Neural Tamper Classification',
      evidence: { tamper_probability: 0.52 },
    },
  ];
  const assessment = getAiAssessment(findings, {}, 'image');

  assert.equal(assessment.executed, true);
  assert.equal(assessment.isProvisional, true);
  assert.equal(assessment.level, 'inconclusive');
  assert.equal(assessment.badgeVariant, 'medium');
  assert.equal(assessment.scoreText, '52%');
  assert.match(assessment.headline, /inconclusive/i);
  assert.match(assessment.explanation, /range of uncertainty/i);
  assert.match(assessment.provisionalNotice, /Milestone G/i);
});

test('getAiAssessment correctly classifies elevated tamper likelihood (> 0.65)', () => {
  const findings = [
    {
      title: 'EfficientNet Splicing Detection',
      evidence: { tamper_probability: 0.88 },
    },
  ];
  const assessment = getAiAssessment(findings, {}, 'image');

  assert.equal(assessment.executed, true);
  assert.equal(assessment.isProvisional, true);
  assert.equal(assessment.level, 'elevated');
  assert.equal(assessment.badgeVariant, 'high');
  assert.equal(assessment.scoreText, '88%');
  assert.match(assessment.headline, /splicing or editing/i);
  assert.match(assessment.explanation, /elevated tamper probability of 88%/i);
});

test('getAiAssessment handles non-image formats by reporting Not Applicable', () => {
  const findings = [];
  const assessment = getAiAssessment(findings, {}, 'pdf');

  assert.equal(assessment.executed, false);
  assert.equal(assessment.available, false);
  assert.equal(assessment.isProvisional, true);
  assert.equal(assessment.level, 'not_applicable');
  assert.equal(assessment.scoreText, 'N/A');
  assert.match(assessment.explanation, /designed for raster image/i);
});

test('evaluateExecutionStatus correctly discriminates Passed, Flagged, Not performed, and Error', () => {
  // 1. Passed
  const passed = evaluateExecutionStatus([]);
  assert.equal(passed.status, 'Passed');
  assert.equal(passed.statusVariant, 'passed');

  // 2. Flagged
  const flagged = evaluateExecutionStatus([{ title: 'Suspicious JS', severity: 'high' }]);
  assert.equal(flagged.status, 'Flagged');
  assert.equal(flagged.statusVariant, 'flagged');

  // 3. Not performed
  const notPerformed = evaluateExecutionStatus([], true, 'Skipped for this format');
  assert.equal(notPerformed.status, 'Not performed');
  assert.equal(notPerformed.statusVariant, 'not_performed');

  // 4. Error
  const errored = evaluateExecutionStatus([{ title: 'Corrupted Object Stream Error', category: 'inconclusive' }]);
  assert.equal(errored.status, 'Error');
  assert.equal(errored.statusVariant, 'error');
});

test('getFileSpecificChecklist generates file-specific checks for PDF documents with execution statuses', () => {
  const findings = [
    {
      title: 'Embedded JavaScript Detected',
      severity: 'high',
      detail: '/JavaScript dictionary found',
    },
    {
      title: 'Corrupted Stream Parser Error',
      category: 'inconclusive',
      detail: 'Failed to parse stream token at byte 1024',
    },
  ];
  const checklist = getFileSpecificChecklist('pdf', 'application/pdf', findings);

  assert.equal(checklist.length, 6);
  const checkIds = checklist.map((c) => c.id);
  assert.deepEqual(checkIds, [
    'pdf_header',
    'pdf_revisions',
    'pdf_scripts',
    'pdf_launch',
    'pdf_typography',
    'pdf_metadata',
  ]);

  const scriptCheck = checklist.find((c) => c.id === 'pdf_scripts');
  assert.equal(scriptCheck.status, 'Flagged');
  assert.equal(scriptCheck.severity, 'high');

  const revisionCheck = checklist.find((c) => c.id === 'pdf_revisions');
  assert.equal(revisionCheck.status, 'Passed');
});

test('getFileSpecificChecklist identifies Not performed sub-checks for Office formats', () => {
  const findings = [
    {
      title: 'Remote Template Injection Target',
      severity: 'high',
      detail: 'word/_rels/settings.xml.rels contacts remote URI',
    },
  ];
  // Pure DOCX: sheet/slide check should be Not performed
  const checklist = getFileSpecificChecklist('docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', findings);

  assert.equal(checklist.length, 6);
  const templateCheck = checklist.find((c) => c.id === 'office_template');
  assert.equal(templateCheck.status, 'Flagged');

  const hiddenCheck = checklist.find((c) => c.id === 'office_hidden');
  assert.equal(hiddenCheck.status, 'Not performed');
});

test('getFileSpecificChecklist identifies Not performed for non-JPEG ELA checks', () => {
  const checklist = getFileSpecificChecklist('bmp', 'image/bmp', []);
  const elaCheck = checklist.find((c) => c.id === 'img_ela');
  assert.equal(elaCheck.status, 'Not performed');
  assert.match(elaCheck.detail, /lossy JPEG DCT/i);
});

test('getFileSpecificChecklist generates file-specific checks for ZIP archives', () => {
  const findings = [
    {
      title: 'Zip Slip Path Traversal Detected',
      severity: 'high',
      detail: 'Member path contains ../../etc/passwd',
    },
  ];
  const checklist = getFileSpecificChecklist('zip', 'application/zip', findings);

  assert.equal(checklist.length, 4);
  const slipCheck = checklist.find((c) => c.id === 'zip_slip');
  assert.equal(slipCheck.status, 'Flagged');
  assert.equal(slipCheck.severity, 'high');

  const bombCheck = checklist.find((c) => c.id === 'zip_bomb');
  assert.equal(bombCheck.status, 'Passed');
});

test('getPlainEnglishVerdict produces appropriate 10-second summaries across risk bands', () => {
  const safeVerdict = getPlainEnglishVerdict(15, 'Low', [], 'image');
  assert.equal(safeVerdict.status, 'safe');
  assert.match(safeVerdict.headline, /Appears Normal/i);

  const cautionVerdict = getPlainEnglishVerdict(45, 'Medium', [{ severity: 'medium' }], 'document');
  assert.equal(cautionVerdict.status, 'caution');
  assert.match(cautionVerdict.headline, /Review Advised/i);

  const dangerVerdict = getPlainEnglishVerdict(85, 'High', [{ severity: 'high' }], 'office');
  assert.equal(dangerVerdict.status, 'danger');
  assert.match(dangerVerdict.headline, /Critical Risk/i);
});

test('calculateExplainableContributions decomposes compound risk into proportional points', () => {
  const findings = [
    { title: 'Embedded JS', severity: 'high', weight: 0.6 },
    { title: 'Inverted Dates', severity: 'medium', weight: 0.2 },
  ];
  const contributions = calculateExplainableContributions(findings, 68);

  assert.equal(contributions.length, 2);
  const totalPoints = contributions.reduce((acc, c) => acc + c.contributionPoints, 0);
  assert.ok(Math.abs(totalPoints - 68) <= 1.0);
  assert.ok(contributions[0].contributionPoints > contributions[1].contributionPoints);
});

test('classifyFindingTaxonomy maps findings accurately across all 5 types', () => {
  assert.equal(classifyFindingTaxonomy({ title: '%%EOF Revision Marker' }).key, 'structural');
  assert.equal(classifyFindingTaxonomy({ title: 'High Shannon Entropy' }).key, 'statistical');
  assert.equal(classifyFindingTaxonomy({ title: 'Suspicious URI Target' }).key, 'heuristic');
  assert.equal(classifyFindingTaxonomy({ title: 'EfficientNet Tamper Probability' }).key, 'machine_learning');
  assert.equal(classifyFindingTaxonomy({ title: 'Unsupported Stream Format' }).key, 'inconclusive');
});
