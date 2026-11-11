/**
 * PRAMAANX — System Constants & Configuration
 * Minimal Light SaaS specifications, navigation routes, and forensic limits.
 */

export const APP_NAME = 'PRAMAANX';
export const APP_TAGLINE = 'Digital Forensics Platform';
export const APP_VERSION = '1.0.0';

// Navigation routes
export const ROUTES = {
  HOME: '/',
  ANALYZE: '/analyze',
  RESULTS: '/analysis/results',
  INVESTIGATIONS: '/investigations',
  VAULT: '/vault',
  REPORTS: '/reports',
  LEARN: '/learn',
  ABOUT: '/about',
  DASHBOARD: '/dashboard',
  SETTINGS: '/settings',
};

// Forensic constraints (aligned with backend config)
export const FORENSIC_LIMITS = {
  MAX_SINGLE_FILE_BYTES: 20 * 1024 * 1024, // 20 MB
  MAX_BATCH_FILES: 10,
  MAX_BATCH_TOTAL_BYTES: 100 * 1024 * 1024, // 100 MB
  MAX_ZIP_ENTRIES: 200,
  MAX_ZIP_UNCOMPRESSED_BYTES: 100 * 1024 * 1024,
};

// Supported forensic format specifications
export const SUPPORTED_EXTENSIONS = [
  '.pdf',
  '.docx',
  '.xlsx',
  '.pptx',
  '.doc',
  '.xls',
  '.ppt',
  '.jpg',
  '.jpeg',
  '.png',
  '.bmp',
  '.tiff',
  '.tif',
  '.zip',
];

export const FILE_ACCEPT_STRING = SUPPORTED_EXTENSIONS.join(',');

export const FORMAT_CATEGORIES = {
  DOCUMENTS: ['PDF'],
  OFFICE: ['DOCX', 'XLSX', 'PPTX', 'DOC', 'XLS', 'PPT'],
  IMAGES: ['JPG', 'JPEG', 'PNG', 'BMP', 'TIFF'],
  ARCHIVES: ['ZIP'],
};

// Calibrated risk levels with light SaaS styling
export const RISK_LEVELS = {
  LOW: {
    label: 'Low Risk',
    maxScore: 30,
    color: '#15803D',
    textColor: '#15803D',
    bgColor: '#DCFCE7',
    borderColor: '#BBF7D0',
  },
  MEDIUM: {
    label: 'Medium Risk',
    maxScore: 69,
    color: '#B45309',
    textColor: '#B45309',
    bgColor: '#FEF3C7',
    borderColor: '#FDE68A',
  },
  HIGH: {
    label: 'High Risk',
    maxScore: 100,
    color: '#B91C1C',
    textColor: '#B91C1C',
    bgColor: '#FEE2E2',
    borderColor: '#FECACA',
  },
};
