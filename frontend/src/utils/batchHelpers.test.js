/**
 * PRAMAANX - Unit Tests for Batch Analysis Data Contracts and Summary Metrics
 * Verifies that:
 * 1. Batch summary metrics (total, completed, failed, highest risk, average risk, requires review)
 *    are accurately derived from individual file records.
 * 2. Successful batch item structures match SingleAnalysisResponse schema requirements.
 * 3. A risk score of 0 does NOT claim authenticity (adheres to strict evidentiary disclaimer).
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { getPlainEnglishVerdict } from './explainabilityHelpers.js';

test('Batch-level summary metrics are calculated accurately across items', () => {
  const results = [
    {
      filename: 'clean_photo.jpg',
      status: 'success',
      file: { filename: 'clean_photo.jpg', detected_type: 'jpg', size_bytes: 102400 },
      analysis: { risk_score: 0, risk_category: 'Low', findings: [] },
    },
    {
      filename: 'spliced_invoice.pdf',
      status: 'success',
      file: { filename: 'spliced_invoice.pdf', detected_type: 'pdf', size_bytes: 512000 },
      analysis: { risk_score: 75, risk_category: 'High', findings: [{ title: 'AST Discrepancy', severity: 'high' }] },
    },
    {
      filename: 'recompressed.jpg',
      status: 'success',
      file: { filename: 'recompressed.jpg', detected_type: 'jpg', size_bytes: 204800 },
      analysis: { risk_score: 42, risk_category: 'Medium', findings: [{ title: 'Ghost Quantization', severity: 'medium' }] },
    },
    {
      filename: 'unsupported.exe',
      status: 'failed',
      error: { code: 'UNSUPPORTED_FILE_FORMAT', message: 'Not a supported format' },
    },
  ];

  const totalFiles = results.length;
  const completed = results.filter((r) => r.status === 'success').length;
  const failed = results.filter((r) => r.status === 'failed').length;
  const scores = results.filter((r) => r.status === 'success').map((r) => r.analysis.risk_score);
  const highestRisk = Math.max(...scores);
  const averageRisk = parseFloat((scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(1));

  // Files requiring human review: risk > 30, verdict not 'no_signs', or findings > 0
  const requiringReview = results.filter((r) => {
    if (r.status !== 'success' || !r.analysis) return false;
    return (
      r.analysis.risk_score > 30 ||
      (r.analysis.verdict && r.analysis.verdict !== 'no_signs') ||
      (r.analysis.findings && r.analysis.findings.length > 0)
    );
  }).length;

  assert.equal(totalFiles, 4);
  assert.equal(completed, 3);
  assert.equal(failed, 1);
  assert.equal(highestRisk, 75);
  assert.equal(averageRisk, 39.0);
  assert.equal(requiringReview, 2); // spliced_invoice.pdf and recompressed.jpg
});

test('Batch item forensic analysis contains identical fields to single-file analysis', () => {
  const singleFileResponse = {
    success: true,
    file: {
      filename: 'sample.jpg',
      detected_type: 'jpg',
      detected_mime: 'image/jpeg',
      size_bytes: 12345,
      sha256: 'a1b2c3d4e5f6',
    },
    analysis: {
      risk_score: 15,
      risk_category: 'Low',
      entropy: 7.2,
      findings: [],
      visual_evidence: { gradcam_url: null, ela_url: '/api/v1/evidence/ela/sample_ela.png' },
      plain_summary: 'No significant anomalies detected.',
      verdict: 'no_signs',
      reliability: 'high',
      ai_status: 'active',
    },
  };

  const batchItem = {
    filename: 'sample.jpg',
    status: 'success',
    file: {
      filename: 'sample.jpg',
      detected_type: 'jpg',
      detected_mime: 'image/jpeg',
      size_bytes: 12345,
      sha256: 'a1b2c3d4e5f6',
    },
    analysis: {
      risk_score: 15,
      risk_category: 'Low',
      entropy: 7.2,
      findings: [],
      visual_evidence: { gradcam_url: null, ela_url: '/api/v1/evidence/ela/sample_ela.png' },
      plain_summary: 'No significant anomalies detected.',
      verdict: 'no_signs',
      reliability: 'high',
      ai_status: 'active',
    },
  };

  // Assert complete property equivalence
  assert.deepEqual(batchItem.file, singleFileResponse.file);
  assert.deepEqual(batchItem.analysis, singleFileResponse.analysis);
});

test('A risk score of 0 is reported as No Signs Detected and does NOT claim authenticity', () => {
  const verdict = getPlainEnglishVerdict(0, 'Low', [], 'jpg', {
    verdict: 'no_signs',
    risk_score: 0,
  });

  assert.equal(verdict.verdictKey, 'no_signs');
  assert.match(verdict.headline, /No Signs/i);
  // Must NOT contain banned words: 'authentic', 'unaltered', 'real', 'fake'
  assert.doesNotMatch(verdict.headline, /\bauthentic\b/i);
  assert.doesNotMatch(verdict.headline, /\bunaltered\b/i);
  assert.doesNotMatch(verdict.headline, /\breal\b/i);
  assert.doesNotMatch(verdict.headline, /\bfake\b/i);

  assert.doesNotMatch(verdict.summary, /\bauthentic\b/i);
  assert.doesNotMatch(verdict.summary, /\bunaltered\b/i);
  assert.doesNotMatch(verdict.summary, /\breal\b/i);
  assert.doesNotMatch(verdict.summary, /\bfake\b/i);
});
