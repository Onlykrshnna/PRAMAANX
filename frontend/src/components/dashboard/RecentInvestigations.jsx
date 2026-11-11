/**
 * PRAMAANX - Recent Investigations Table (Light SaaS Theme)
 * Clean tabular view of forensic case records with sample demonstration dataset.
 */

import { useState } from 'react';
import Card from '../common/Card';
import Badge from '../common/Badge';
import Button from '../common/Button';
import {
  FileText,
  Image as ImageIcon,
  Archive,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  FolderOpen,
} from 'lucide-react';
import { getRiskLevel } from '../../utils/riskHelpers';

const DEMO_INVESTIGATIONS = [
  {
    id: 'case-0941',
    filename: 'executive_payroll_q4.pdf',
    type: 'pdf',
    date: '2026-11-04 19:42 UTC',
    riskScore: 88,
    status: 'Completed',
    leadIndicator: 'Embedded JavaScript & Incremental Revisions (%%EOF)',
  },
  {
    id: 'case-0940',
    filename: 'id_badge_tampered_v2.png',
    type: 'png',
    date: '2026-11-04 18:15 UTC',
    riskScore: 78,
    status: 'Completed',
    leadIndicator: 'EfficientNet-B0 Tamper Probability (0.84) & ELA Discontinuity',
  },
  {
    id: 'case-0939',
    filename: 'contract_amendment_final.docx',
    type: 'docx',
    date: '2026-11-04 17:05 UTC',
    riskScore: 65,
    status: 'Completed',
    leadIndicator: 'Vanished / White-on-White Text & Stripped Author Metadata',
  },
  {
    id: 'case-0938',
    filename: 'vendor_audit_evidence.zip',
    type: 'zip',
    date: '2026-11-04 15:30 UTC',
    riskScore: 15,
    status: 'Verified',
    leadIndicator: 'Clean Structure — Zero Path Traversal or Archive Bombs',
  },
  {
    id: 'case-0937',
    filename: 'board_financial_deck.pptx',
    type: 'pptx',
    date: '2026-11-04 14:12 UTC',
    riskScore: 22,
    status: 'Verified',
    leadIndicator: 'Single Hidden Slide Detected (Non-Malicious Content)',
  },
];

export default function RecentInvestigations({ onViewAll }) {
  const [filter, setFilter] = useState('all');

  const filteredItems = DEMO_INVESTIGATIONS.filter((item) => {
    if (filter === 'high') return item.riskScore >= 70;
    if (filter === 'medium') return item.riskScore >= 31 && item.riskScore < 70;
    if (filter === 'low') return item.riskScore <= 30;
    return true;
  });

  const getFormatIcon = (type) => {
    switch (type) {
      case 'pdf':
      case 'docx':
      case 'pptx':
      case 'xlsx':
        return <FileText className="w-4 h-4 text-[var(--accent-cobalt)]" />;
      case 'png':
      case 'jpg':
      case 'jpeg':
        return <ImageIcon className="w-4 h-4 text-[#7C3AED]" />;
      case 'zip':
        return <Archive className="w-4 h-4 text-[var(--status-medium)]" />;
      default:
        return <FileText className="w-4 h-4 text-[var(--text-muted)]" />;
    }
  };

  return (
    <Card
      title="Recent Forensic Investigations"
      subtitle="Latest digital evidence cases processed through the multi-engine pipeline"
      headerIcon={FolderOpen}
      headerBadge={
        <Badge variant="demo" size="sm">
          DEMO DATA
        </Badge>
      }
      action={
        <div className="flex items-center gap-2">
          {/* Quick Filter Tabs */}
          <div className="hidden sm:flex items-center p-0.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
            {['all', 'high', 'medium', 'low'].map((tab) => (
              <button
                key={tab}
                type="button"
                onClick={() => setFilter(tab)}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-all capitalize ${
                  filter === tab
                    ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-xs'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
          {onViewAll && (
            <Button
              variant="outline"
              size="sm"
              icon={ArrowRight}
              iconPosition="right"
              onClick={onViewAll}
            >
              View All
            </Button>
          )}
        </div>
      }
      bodyClassName="p-0"
    >
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-[var(--bg-subtle)] border-b border-[var(--border-hairline)] text-[var(--text-muted)] uppercase tracking-wider font-mono text-[10px]">
            <tr>
              <th className="px-5 py-3">Evidence File</th>
              <th className="px-4 py-3">Format</th>
              <th className="px-4 py-3">Analysis Date</th>
              <th className="px-4 py-3">Risk Score</th>
              <th className="px-4 py-3">Classification</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-5 py-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#F1F5F9]">
            {filteredItems.map((item) => {
              const risk = getRiskLevel(item.riskScore);
              return (
                <tr
                  key={item.id}
                  className="hover:bg-[var(--bg-subtle)] transition-colors"
                >
                  {/* File & Lead Indicator */}
                  <td className="px-5 py-3.5">
                    <div className="flex items-center gap-2.5">
                      <div className="p-1.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
                        {getFormatIcon(item.type)}
                      </div>
                      <div>
                        <div className="font-semibold text-[var(--text-primary)]">
                          {item.filename}
                        </div>
                        <div className="text-[11px] text-[var(--text-muted)] max-w-xs truncate">
                          {item.leadIndicator}
                        </div>
                      </div>
                    </div>
                  </td>

                  {/* Format */}
                  <td className="px-4 py-3.5">
                    <span className="font-mono uppercase text-[var(--text-secondary)] px-2 py-0.5 rounded bg-[var(--bg-subtle)] border border-[var(--border-hairline)] text-[10px] font-medium">
                      {item.type}
                    </span>
                  </td>

                  {/* Timestamp */}
                  <td className="px-4 py-3.5 text-[var(--text-muted)] font-mono text-[11px] whitespace-nowrap">
                    {item.date}
                  </td>

                  {/* Risk Score */}
                  <td className="px-4 py-3.5 font-mono">
                    <div className="flex items-center gap-1.5">
                      <span className="font-bold text-[var(--text-primary)]">
                        {item.riskScore}
                      </span>
                      <span className="text-[11px] text-[var(--text-subtle)]">/100</span>
                    </div>
                  </td>

                  {/* Risk Badge */}
                  <td className="px-4 py-3.5">
                    <span
                      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${risk.badgeClass}`}
                    >
                      {risk.key === 'low' && <ShieldCheck className="w-3.5 h-3.5" />}
                      {risk.key === 'medium' && (
                        <AlertTriangle className="w-3.5 h-3.5" />
                      )}
                      {risk.key === 'high' && <ShieldAlert className="w-3.5 h-3.5" />}
                      {risk.label}
                    </span>
                  </td>

                  {/* Status */}
                  <td className="px-4 py-3.5">
                    <span className="inline-flex items-center gap-1.5 text-xs text-[var(--text-secondary)] font-medium">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#15803D]" />
                      {item.status}
                    </span>
                  </td>

                  {/* Action */}
                  <td className="px-5 py-3.5 text-right whitespace-nowrap">
                    <Button
                      variant="ghost"
                      size="sm"
                      icon={ExternalLink}
                      iconPosition="right"
                      onClick={() => alert(`Inspection details for ${item.filename} (Demo Record)`)}
                    >
                      Inspect
                    </Button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
