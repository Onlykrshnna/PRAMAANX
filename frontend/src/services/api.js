/**
 * PRAMAANX - Centralized API Service
 * Configures Axios client with base URL, timeout, and standardized error normalization.
 */

import axios from 'axios';

// Vite proxy handles '/api/v1' during development; fallback to explicit host
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 60000, // 60 seconds for heavy ML and deep parsing runs
  headers: {
    Accept: 'application/json',
  },
});

// Response interceptor to normalize error schemas
apiClient.interceptors.response.use(
  (response) => response.data,
  (error) => {
    // If backend returned a structured ErrorResponse with error object
    if (error.response?.data?.error) {
      return Promise.reject(error.response.data.error);
    }

    const responseData = error.response?.data;
    let detailMessage = null;

    if (responseData?.detail) {
      if (typeof responseData.detail === 'string') {
        detailMessage = responseData.detail;
      } else if (typeof responseData.detail === 'object') {
        if (responseData.detail.message) {
          detailMessage = responseData.detail.message;
        } else if (Array.isArray(responseData.detail)) {
          // FastAPI standard validation error list
          detailMessage = responseData.detail
            .map((item) => item.msg || JSON.stringify(item))
            .join('; ');
        }
      }
    }

    // Default normalized error
    const normalizedError = {
      code:
        responseData?.detail?.code ||
        error.code ||
        (error.response?.status === 413 ? 'FILE_TOO_LARGE' : null) ||
        (error.response?.status === 415 ? 'UNSUPPORTED_MEDIA' : null) ||
        'NETWORK_ERROR',
      message:
        detailMessage ||
        (error.response?.status === 413
          ? 'File size exceeds maximum allowable limit.'
          : null) ||
        (error.response?.status === 415
          ? 'Uploaded format is unsupported for forensic analysis.'
          : null) ||
        error.message ||
        'Unable to communicate with PRAMAANX forensic backend.',
      status: error.response?.status || 500,
      details: responseData?.detail?.details || {},
    };

    return Promise.reject(normalizedError);
  }
);

// ==============================================================================
// Investigation & Evidence Vault API Services (Milestone D)
// ==============================================================================

export const getInvestigations = (params = {}) => {
  return apiClient.get('/investigations', { params });
};

export const createInvestigation = (data) => {
  return apiClient.post('/investigations', data);
};

export const getInvestigation = (caseId) => {
  return apiClient.get(`/investigations/${caseId}`);
};

export const updateInvestigation = (caseId, data) => {
  return apiClient.patch(`/investigations/${caseId}`, data);
};

export const uploadEvidenceToCase = (caseId, file, onUploadProgress) => {
  const formData = new FormData();
  formData.append('file', file);
  return apiClient.post(`/investigations/${caseId}/evidence`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress,
  });
};

export const getEvidenceVaultItems = (params = {}) => {
  return apiClient.get('/evidence', { params });
};

export const getEvidenceDetail = (evidenceId) => {
  return apiClient.get(`/evidence/${evidenceId}`);
};

export const verifyEvidenceIntegrity = (evidenceId) => {
  return apiClient.post(`/evidence/${evidenceId}/verify`);
};

export const getEvidenceDownloadUrl = (evidenceId) => {
  const base = import.meta.env.VITE_API_BASE_URL || '/api/v1';
  return `${base}/evidence/${evidenceId}/download`;
};

export const getEvidenceAnalysisHistory = (caseId, evidenceId) => {
  return apiClient.get(`/investigations/${caseId}/evidence/${evidenceId}/history`);
};

export const reanalyzeEvidence = (caseId, evidenceId) => {
  return apiClient.post(`/investigations/${caseId}/evidence/${evidenceId}/reanalyze`);
};

export const getCaseAuditLogs = (caseId) => {
  return apiClient.get(`/investigations/${caseId}/audit`);
};

// ============================================================================
// Forensic Reports API (Milestone E)
// ============================================================================

export const generateCaseReport = (caseId, { report_type = 'detailed', title, examiner } = {}) => {
  return apiClient.post(`/investigations/${caseId}/reports`, {
    report_type,
    title,
    examiner,
  });
};

export const getReports = ({ case_id, report_type, limit = 50, offset = 0 } = {}) => {
  return apiClient.get('/reports', {
    params: {
      case_id,
      report_type,
      limit,
      offset,
    },
  });
};

export const getReportDetail = (reportId) => {
  return apiClient.get(`/reports/${reportId}`);
};

export const resolveMediaUrl = (path) => {
  if (!path) return null;
  if (
    path.startsWith('http://') ||
    path.startsWith('https://') ||
    path.startsWith('blob:') ||
    path.startsWith('data:')
  ) {
    return path;
  }
  const base = import.meta.env.VITE_API_BASE_URL || '';
  if (base.startsWith('http')) {
    try {
      const origin = new URL(base).origin;
      return `${origin}${path.startsWith('/') ? '' : '/'}${path}`;
    } catch {
      return path;
    }
  }
  return path;
};

export const getReportDownloadUrl = (reportId) => {
  const baseURL = (import.meta.env.VITE_API_BASE_URL || '/api/v1').replace(/\/+$/, '');
  return `${baseURL}/reports/${reportId}/download`;
};

export const getReportPreviewUrl = (reportId) => {
  const baseURL = (import.meta.env.VITE_API_BASE_URL || '/api/v1').replace(/\/+$/, '');
  return `${baseURL}/reports/${reportId}/preview`;
};

export default apiClient;

