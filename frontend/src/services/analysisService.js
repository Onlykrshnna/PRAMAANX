/**
 * PRAMAANX - Forensic Analysis Service
 * Manages multipart uploads and dispatches to FastAPI forensic endpoints:
 * - Single file: POST /api/v1/analyze
 * - Batch files: POST /api/v1/analyze/batch
 * - ZIP archive: POST /api/v1/analyze/archive
 */

import { apiClient } from './api';

/**
 * Inspect a single document or image file.
 * @param {File} file - Browser File object
 * @param {Function} [onProgress] - Optional upload progress callback
 * @returns {Promise<Object>} SingleAnalysisResponse
 */
export async function analyzeSingleFile(file, onProgress) {
  const formData = new FormData();
  formData.append('file', file);

  return apiClient.post('/analyze', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (progressEvent) => {
      if (onProgress && progressEvent.total) {
        const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        onProgress(percent);
      }
    },
  });
}

/**
 * Inspect multiple documents or images in batch (up to 10 files).
 * @param {File[]} files - Array of browser File objects
 * @param {Function} [onProgress] - Optional upload progress callback
 * @returns {Promise<Object>} BatchAnalysisResponse
 */
export async function analyzeBatch(files, onProgress) {
  const formData = new FormData();
  files.forEach((file) => {
    formData.append('files', file);
  });

  return apiClient.post('/analyze/batch', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (progressEvent) => {
      if (onProgress && progressEvent.total) {
        const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        onProgress(percent);
      }
    },
  });
}

/**
 * Inspect a ZIP archive through hardened pre-extraction sandbox screening.
 * @param {File} zipFile - Browser File object for the ZIP file
 * @param {Function} [onProgress] - Optional upload progress callback
 * @returns {Promise<Object>} ArchiveAnalysisResponse
 */
export async function analyzeArchive(zipFile, onProgress) {
  const formData = new FormData();
  formData.append('file', zipFile);

  return apiClient.post('/analyze/archive', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    onUploadProgress: (progressEvent) => {
      if (onProgress && progressEvent.total) {
        const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
        onProgress(percent);
      }
    },
  });
}

