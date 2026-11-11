/**
 * PRAMAANX - Data Formatters
 * Utility functions for displaying file sizes, dates, hashes, and numbers.
 */

/**
 * Formats byte values into human-readable strings (KB, MB, GB).
 */
export function formatBytes(bytes, decimals = 2) {
  if (bytes === 0 || !bytes) return '0 B';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

/**
 * Formats an ISO 8601 date string or timestamp into a professional forensic timestamp.
 * Format: YYYY-MM-DD HH:mm:ss UTC
 */
export function formatForensicDate(dateString) {
  if (!dateString) return '—';
  try {
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return dateString;
    return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  } catch {
    return dateString;
  }
}

/**
 * Truncates a 64-character SHA-256 hash for compact tabular views.
 * Example: '5a4d...9f12'
 */
export function truncateHash(hash, leading = 6, trailing = 6) {
  if (!hash || hash.length <= leading + trailing) return hash || '—';
  return `${hash.substring(0, leading)}...${hash.substring(hash.length - trailing)}`;
}

/**
 * Capitalizes string safely.
 */
export function capitalize(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
}

