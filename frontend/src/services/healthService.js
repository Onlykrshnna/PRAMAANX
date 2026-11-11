/**
 * PRAMAANX - Backend Health Service
 * Queries the FastAPI /health endpoint to monitor engine availability and model statuses.
 */

import { apiClient } from './api';

export async function checkBackendHealth() {
  try {
    const data = await apiClient.get('/health', {
      timeout: 5000,
    });
    return {
      isOnline: true,
      data,
      error: null,
    };
  } catch (err) {
    return {
      isOnline: false,
      data: null,
      error: err.message || 'Backend offline',
    };
  }
}

