/**
 * PRAMAANX - Risk Classification & Color Helpers
 * Translates numeric risk scores (0-100) into calibrated forensic risk bands (Light Theme).
 */

import { RISK_LEVELS } from './constants';

export function getRiskLevel(score) {
  const numeric = Number(score) || 0;
  if (numeric <= RISK_LEVELS.LOW.maxScore) {
    return {
      key: 'low',
      ...RISK_LEVELS.LOW,
      badgeClass: 'text-[#15803D] bg-[#DCFCE7] border-[#BBF7D0]',
      pillClass: 'bg-[#15803D]',
      barClass: 'bg-[#15803D]',
    };
  }
  if (numeric <= RISK_LEVELS.MEDIUM.maxScore) {
    return {
      key: 'medium',
      ...RISK_LEVELS.MEDIUM,
      badgeClass: 'text-[#B45309] bg-[#FEF3C7] border-[#FDE68A]',
      pillClass: 'bg-[#B45309]',
      barClass: 'bg-[#B45309]',
    };
  }
  return {
    key: 'high',
    ...RISK_LEVELS.HIGH,
    badgeClass: 'text-[#B91C1C] bg-[#FEE2E2] border-[#FECACA]',
    pillClass: 'bg-[#B91C1C]',
    barClass: 'bg-[#B91C1C]',
  };
}

export function getRiskCategoryLabel(score) {
  return getRiskLevel(score).label;
}
