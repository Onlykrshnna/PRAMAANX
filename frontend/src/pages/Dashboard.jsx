/**
 * PRAMAANX - Simplified Light SaaS Dashboard Page
 * Accessible via /dashboard. Presents high-level metrics, threat spread, and recent cases.
 */

import { useNavigate } from 'react-router-dom';
import PageHeader from '../components/layout/PageHeader';
import Button from '../components/common/Button';
import Badge from '../components/common/Badge';
import StatCard from '../components/dashboard/StatCard';
import RiskDistribution from '../components/dashboard/RiskDistribution';
import RecentInvestigations from '../components/dashboard/RecentInvestigations';
import QuickActions from '../components/dashboard/QuickActions';
import {
  FileSearch,
  Files,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  Info,
} from 'lucide-react';
import { ROUTES } from '../utils/constants';

export default function Dashboard() {
  const navigate = useNavigate();

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <PageHeader
        title="Forensic Operations Dashboard"
        subtitle="Operational overview of file inspections, detected anomalies, and case throughput."
        badge={
          <Badge variant="demo" size="sm">
            DEMONSTRATION DATA
          </Badge>
        }
        actions={
          <Button
            variant="primary"
            icon={FileSearch}
            onClick={() => navigate(ROUTES.ANALYZE)}
          >
            Start New Analysis
          </Button>
        }
      />

      {/* Demonstration Banner */}
      <div className="flex items-center gap-3 p-4 rounded-xl bg-[var(--bg-surface)] border border-[var(--border-hairline)] text-xs text-[var(--text-secondary)] shadow-xs">
        <Info className="w-4 h-4 text-[var(--accent-cobalt)] shrink-0" />
        <div>
          <span className="font-semibold text-[var(--text-primary)]">
            Demonstration Mode:
          </span>{' '}
          Statistics and recent cases displayed below represent a sample baseline. Live evidence analyses submitted via the Analyze page will appear here.
        </div>
      </div>

      {/* 4 Statistics Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Files Screened"
          value="104"
          subtitle="Processed across all formats"
          icon={Files}
          variant="neutral"
          trendText="+12 this session"
          isDemo={true}
        />
        <StatCard
          title="High-Risk Anomalies"
          value="12"
          subtitle="Exploits / tampering / disguise"
          icon={ShieldAlert}
          variant="high"
          trendText="11.5% of total"
          isDemo={true}
        />
        <StatCard
          title="Medium-Risk Indicators"
          value="24"
          subtitle="Suspicious metadata / tags"
          icon={AlertTriangle}
          variant="medium"
          trendText="23.1% of total"
          isDemo={true}
        />
        <StatCard
          title="Verified Low-Risk Files"
          value="68"
          subtitle="Structural integrity verified"
          icon={ShieldCheck}
          variant="low"
          trendText="65.4% of total"
          isDemo={true}
        />
      </div>

      {/* Threat Spread & Recent Cases */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <RecentInvestigations
            onViewAll={() => navigate(ROUTES.INVESTIGATIONS)}
          />
        </div>
        <div className="lg:col-span-1">
          <RiskDistribution
            lowCount={68}
            mediumCount={24}
            highCount={12}
            isDemo={true}
          />
        </div>
      </div>

      {/* Quick Launch Actions */}
      <div className="space-y-3">
        <div>
          <h3 className="text-base font-bold text-[var(--text-primary)] tracking-tight">
            Quick Actions
          </h3>
          <p className="text-xs text-[var(--text-muted)]">
            Launch new inspection workflows or view compiled forensic reports
          </p>
        </div>
        <QuickActions />
      </div>
    </div>
  );
}
