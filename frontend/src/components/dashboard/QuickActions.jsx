/**
 * PRAMAANX - Quick Actions Component (Light SaaS Theme)
 * Action triggers routing to Single File Upload, Batch Queue, and Reports.
 */

import { useNavigate } from 'react-router-dom';
import Card from '../common/Card';
import { FileSearch, Layers, FileDown, ArrowRight } from 'lucide-react';
import { ROUTES } from '../../utils/constants';

export default function QuickActions() {
  const navigate = useNavigate();

  const ACTIONS = [
    {
      title: 'Analyze Single File',
      description: 'Upload a document or image (PDF, Office, Image) for deep multi-engine forensic screening.',
      icon: FileSearch,
      iconColor: 'text-[var(--accent-cobalt)]',
      actionText: 'Launch Inspector',
      onClick: () => navigate(ROUTES.ANALYZE),
      badge: 'Up to 20 MB',
    },
    {
      title: 'Batch Analysis',
      description: 'Concurrent inspection of up to 10 files or hardened ZIP archives with isolated error screening.',
      icon: Layers,
      iconColor: 'text-[#7C3AED]',
      actionText: 'Open Batch Queue',
      onClick: () => navigate(`${ROUTES.ANALYZE}?mode=batch`),
      badge: 'Max 100 MB',
    },
    {
      title: 'Forensic Reports',
      description: 'Generate, preview, and download cryptographically stamped PDF forensic reports for legal chains of custody.',
      icon: FileDown,
      iconColor: 'text-[var(--status-medium)]',
      actionText: 'View Reports',
      onClick: () => navigate(ROUTES.REPORTS),
      badge: 'PDF Export',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {ACTIONS.map((action, idx) => {
        const Icon = action.icon;
        return (
          <Card
            key={idx}
            onClick={action.onClick}
            className="group hover:border-[var(--border-strong)] transition-all cursor-pointer flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="p-2.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)] text-[var(--text-primary)] group-hover:border-[var(--border-strong)] transition-colors">
                  <Icon className={`w-5 h-5 ${action.iconColor}`} />
                </div>
                <span className="text-[11px] font-mono font-medium px-2 py-0.5 rounded-full bg-[var(--bg-subtle)] border border-[var(--border-hairline)] text-[var(--text-muted)]">
                  {action.badge}
                </span>
              </div>
              <h4 className="text-sm font-bold text-[var(--text-primary)] group-hover:text-[var(--accent-cobalt)] transition-colors">
                {action.title}
              </h4>
              <p className="text-xs text-[var(--text-muted)] mt-1.5 leading-relaxed">
                {action.description}
              </p>
            </div>

            <div className="flex items-center gap-1.5 text-xs font-semibold text-[var(--text-primary)] group-hover:text-[var(--accent-cobalt)] mt-5 pt-3 border-t border-[var(--border-hairline)]">
              <span>{action.actionText}</span>
              <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
            </div>
          </Card>
        );
      })}
    </div>
  );
}
