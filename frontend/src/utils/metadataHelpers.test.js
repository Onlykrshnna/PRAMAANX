/**
 * PRAMAANX - Unit Tests for Forensic Metadata Helpers
 * ===================================================
 * Verifies format-specific field mapping, status assignment (Available, Missing, Unreadable, Not examined),
 * overview calculations, timestamp distinction, and safe metadata sanitization.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  sanitizeMetadataValue,
  determineFieldStatus,
  buildMetadataReport,
} from './metadataHelpers.js';

test('sanitizeMetadataValue safely escapes HTML tags, scripts, and strips control chars', () => {
  const unsafe = '<script>alert("xss")</script>\x00\x08Admin & User';
  const sanitized = sanitizeMetadataValue(unsafe);

  assert.ok(!sanitized.includes('<script>'));
  assert.ok(sanitized.includes('&lt;script&gt;'));
  assert.ok(sanitized.includes('&amp;'));
  assert.ok(!sanitized.includes('\x00'));
  assert.ok(!sanitized.includes('\x08'));
});

test('determineFieldStatus accurately discriminates Available, Missing, Unreadable, and Not examined', () => {
  assert.equal(determineFieldStatus('Canon EOS 5D Mark IV'), 'Available');
  assert.equal(determineFieldStatus(null), 'Missing');
  assert.equal(determineFieldStatus(''), 'Missing');
  assert.equal(determineFieldStatus(undefined), 'Missing');
  assert.equal(determineFieldStatus('Corrupted\uFFFDDate'), 'Unreadable');
  assert.equal(determineFieldStatus('Canon', false), 'Not examined');
});

test('buildMetadataReport correctly populates Image metadata fields and counts', () => {
  const rawMeta = {
    camera_make: 'Sony',
    camera_model: 'Alpha 7 IV',
    datetime_original: '2026-05-12 11:20:00',
    dimensions: '3840 × 2160',
    software: 'Adobe Photoshop Lightroom',
    color_space: 'sRGB',
    has_icc_profile: true,
    icc_profile_size: 3144,
    orientation: '1',
  };

  const report = buildMetadataReport('jpeg', 'image/jpeg', rawMeta);

  assert.equal(report.formatCategory, 'Image');
  assert.equal(report.fields.length, 9);

  const makeField = report.fields.find((f) => f.id === 'img_camera');
  assert.equal(makeField.value, 'Sony Alpha 7 IV');
  assert.equal(makeField.status, 'Available');
  assert.equal(makeField.source, 'EXIF / IFD0 (0x010F & 0x0110)');

  const dtField = report.fields.find((f) => f.id === 'img_dt_orig');
  assert.equal(dtField.value, '2026-05-12 11:20:00');
  assert.equal(dtField.status, 'Available');
  assert.equal(dtField.isTimestamp, true);

  const gpsField = report.fields.find((f) => f.id === 'img_gps');
  assert.equal(gpsField.status, 'Missing');
  assert.equal(gpsField.value, null);

  assert.ok(report.overview.totalExamined === 9);
  assert.ok(report.overview.availableCount >= 6);
  assert.ok(report.overview.missingCount >= 1);
});

test('buildMetadataReport handles PDF metadata fields and XMP presence', () => {
  const rawMeta = {
    author: 'Legal Counsel',
    title: 'Declaration of Authenticity',
    subject: 'Evidence Docket 2026-004',
    creator: 'Microsoft Word',
    producer: 'Adobe PDF Library 15.0',
    creation_date_iso: '2026-02-14T08:30:00+00:00',
    mod_date_iso: '2026-02-14T09:15:00+00:00',
    has_xmp: true,
  };

  const report = buildMetadataReport('pdf', 'application/pdf', rawMeta);

  assert.equal(report.formatCategory, 'PDF');
  assert.equal(report.fields.length, 8);

  const authorField = report.fields.find((f) => f.id === 'pdf_author');
  assert.equal(authorField.value, 'Legal Counsel');
  assert.equal(authorField.status, 'Available');

  const xmpField = report.fields.find((f) => f.id === 'pdf_xmp');
  assert.equal(xmpField.status, 'Available');
  assert.match(xmpField.value, /Extensible Metadata Platform/i);

  assert.equal(report.overview.totalExamined, 8);
  assert.equal(report.overview.availableCount, 8);
  assert.equal(report.overview.missingCount, 0);
});

test('buildMetadataReport handles Office document metadata fields and application properties', () => {
  const rawMeta = {
    creator: 'Auditor Jane',
    last_modified_by: 'Reviewer Bob',
    created_iso: '2026-01-10T10:00:00Z',
    modified_iso: '2026-01-11T12:00:00Z',
    application: 'Microsoft Word',
    app_version: '16.0000',
    company: 'Financial Intelligence Unit',
    title: 'Audit Findings',
    subject: 'Internal Controls',
  };

  const report = buildMetadataReport('docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', rawMeta);

  assert.equal(report.formatCategory, 'Office Document');
  assert.equal(report.fields.length, 8);

  const appField = report.fields.find((f) => f.id === 'office_application');
  assert.equal(appField.value, 'Microsoft Word (v16.0000)');
  assert.equal(appField.status, 'Available');

  const companyField = report.fields.find((f) => f.id === 'office_company');
  assert.equal(companyField.value, 'Financial Intelligence Unit');
  assert.equal(companyField.status, 'Available');
});

test('buildMetadataReport handles ZIP archive metadata fields and member inventory', () => {
  const rawMeta = {
    entries: [
      { name: 'document.pdf', timestamp: '2026-04-01 10:00:00', compress_type: 'Deflate', crc32: '0xA1B2C3D4' },
      { name: 'photo.jpg', timestamp: '2026-04-01 10:05:00', compress_type: 'Deflate', crc32: '0x99887766' },
    ],
    comment: 'Official forensic archive package',
  };

  const report = buildMetadataReport('zip', 'application/zip', rawMeta);

  assert.equal(report.formatCategory, 'ZIP Archive');
  assert.equal(report.fields.length, 5);

  const entriesField = report.fields.find((f) => f.id === 'zip_entry_names');
  assert.equal(entriesField.status, 'Available');
  assert.match(entriesField.value, /document\.pdf/);

  const crcField = report.fields.find((f) => f.id === 'zip_crc32');
  assert.equal(crcField.status, 'Available');
  assert.match(crcField.value, /0xA1B2C3D4/);

  const commentField = report.fields.find((f) => f.id === 'zip_comment');
  assert.equal(commentField.value, 'Official forensic archive package');
  assert.equal(commentField.status, 'Available');
});

test('buildMetadataReport treats completely stripped metadata cleanly without crashing or false suspicion', () => {
  // Simulates an image stripped by a privacy-preserving messenger
  const report = buildMetadataReport('jpeg', 'image/jpeg', {});

  assert.equal(report.formatCategory, 'Image');
  assert.equal(report.overview.totalExamined, 9);
  assert.equal(report.overview.availableCount, 0);
  assert.equal(report.overview.missingCount, 9);
  assert.equal(report.overview.unreadableCount, 0);
});

