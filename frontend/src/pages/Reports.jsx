/**
 * PRAMAANX - Reports Archive Page (Light SaaS Theme - Milestone E)
 * Generates and manages downloadable court-grade PDF forensic examination reports,
 * executive summaries, and cryptographic SHA-256 export certificates.
 */

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import PageHeader from '../components/layout/PageHeader';
import Card from '../components/common/Card';
import Badge from '../components/common/Badge';
import Button from '../components/common/Button';
import Modal from '../components/common/Modal';
import LoadingSpinner from '../components/common/LoadingSpinner';
import EmptyState from '../components/common/EmptyState';
import {
  FileText,
  Download,
  Eye,
  Plus,
  Search,
  Filter,
  Copy,
  Check,
  ExternalLink,
  RefreshCw,
  AlertTriangle,
  FileCheck,
  Shield,
} from 'lucide-react';
import {
  getReports,
  generateCaseReport,
  getInvestigations,
  getReportDownloadUrl,
  getReportPreviewUrl,
} from '../services/api';
import { formatBytes, formatForensicDate } from '../utils/formatters';
import { ROUTES } from '../utils/constants';

export default function Reports() {
  const navigate = useNavigate();

  // Reports catalog state
  const [reports, setReports] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('all'); // 'all' | 'executive' | 'detailed'
  const [caseFilter, setCaseFilter] = useState('all');

  // Available cases for report generation & filter
  const [availableCases, setAvailableCases] = useState([]);

  // Generate Report Modal
  const [isGenerateModalOpen, setIsGenerateModalOpen] = useState(false);
  const [selectedCaseId, setSelectedCaseId] = useState('');
  const [selectedReportType, setSelectedReportType] = useState('detailed');
  const [customTitle, setCustomTitle] = useState('');
  const [examinerName, setExaminerName] = useState('Forensic Examiner');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generateError, setGenerateError] = useState(null);

  // PDF Preview Modal
  const [previewReport, setPreviewReport] = useState(null);
  const [copiedHash, setCopiedHash] = useState(null);

  // Fetch investigations for case selection dropdown
  useEffect(() => {
    getInvestigations({ limit: 100 })
      .then((res) => {
        const list = res.investigations || [];
        setAvailableCases(list);
        if (list.length > 0) {
          setSelectedCaseId(list[0].id);
        }
      })
      .catch(() => setAvailableCases([]));
  }, []);

  // Fetch reports catalog
  const fetchReportsList = async (showLoading = true) => {
    if (showLoading) setIsLoading(true);
    setFetchError(null);
    try {
      const res = await getReports({
        case_id: caseFilter === 'all' ? undefined : caseFilter,
        report_type: typeFilter === 'all' ? undefined : typeFilter,
      });
      setReports(res.reports || []);
      setTotalCount(res.total || 0);
    } catch (err) {
      setFetchError(err.message || 'Failed to retrieve reports from server.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    let ignore = false;
    const load = async () => {
      try {
        const res = await getReports({
          case_id: caseFilter === 'all' ? undefined : caseFilter,
          report_type: typeFilter === 'all' ? undefined : typeFilter,
        });
        if (!ignore) {
          setReports(res.reports || []);
          setTotalCount(res.total || 0);
          setFetchError(null);
        }
      } catch (err) {
        if (!ignore) {
          setFetchError(err.message || 'Failed to retrieve reports from server.');
        }
      } finally {
        if (!ignore) {
          setIsLoading(false);
        }
      }
    };
    load();
    return () => {
      ignore = true;
    };
  }, [caseFilter, typeFilter]);

  // Handle report generation
  const handleGenerateReport = async (e) => {
    e.preventDefault();
    if (!selectedCaseId) {
      setGenerateError('Please select a valid investigation case.');
      return;
    }

    setIsGenerating(true);
    setGenerateError(null);
    try {
      const res = await generateCaseReport(selectedCaseId, {
        report_type: selectedReportType,
        title: customTitle.trim() || undefined,
        examiner: examinerName.trim() || undefined,
      });

      setIsGenerateModalOpen(false);
      setCustomTitle('');
      await fetchReportsList(false);

      if (res.report) {
        setPreviewReport(res.report);
      }
    } catch (err) {
      setGenerateError(err.message || 'Report generation failed.');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Filter reports by search query
  const filteredReports = reports.filter((r) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      r.id.toLowerCase().includes(q) ||
      (r.title && r.title.toLowerCase().includes(q)) ||
      (r.investigation_id && r.investigation_id.toLowerCase().includes(q)) ||
      (r.sha256 && r.sha256.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      <PageHeader
        title="Forensic Reports Library"
        subtitle="Automated compilation of court-grade PDF inspection reports, executive briefs, and tamper-evident SHA-256 certificates."
        badge={
          <Badge variant="neutral" size="sm">
            IMMUTABLE CERTIFICATES
          </Badge>
        }
        actions={
          <Button
            variant="accent"
            icon={Plus}
            onClick={() => setIsGenerateModalOpen(true)}
          >
            Generate New Report
          </Button>
        }
      />

      {/* Report Specifications Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card title="Chain of Custody" headerIcon={Shield}>
          <p className="text-xs text-[var(--text-muted)] leading-relaxed">
            Every exported report includes file sizes, exact ingest timestamps, baseline SHA-256 fingerprints, and calibrated Noisy-OR risk scores.
          </p>
        </Card>

        <Card title="Traceability & Offsets" headerIcon={FileCheck}>
          <p className="text-xs text-[var(--text-muted)] leading-relaxed">
            Technical findings link to exact byte offsets, PDF object IDs, and container paths, with visual references to Grad-CAM and ELA maps.
          </p>
        </Card>

        <Card title="Executive & Detailed Modes" headerIcon={FileText}>
          <p className="text-xs text-[var(--text-muted)] leading-relaxed">
            Generate concise executive risk briefs for leadership or exhaustive multi-page forensic dossiers with complete audit logs.
          </p>
        </Card>
      </div>

      {/* Filter and Search Bar */}
      <Card bodyClassName="p-4">
        <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
          <div className="relative w-full sm:w-80">
            <Search className="absolute left-3 top-2.5 w-4 h-4 text-[var(--text-muted)]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search reports by ID, title, or SHA-256..."
              className="w-full pl-9 pr-4 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] placeholder-[#94A3B8] border border-[var(--border-hairline)] rounded-lg focus:outline-none focus:border-[#2563EB]"
            />
          </div>

          <div className="flex flex-wrap items-center gap-3 w-full sm:w-auto">
            {/* Case Filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-[var(--text-muted)]">Case:</span>
              <select
                value={caseFilter}
                onChange={(e) => setCaseFilter(e.target.value)}
                className="px-2.5 py-1.5 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] border border-[var(--border-strong)] rounded-lg focus:outline-none focus:border-[#2563EB]"
              >
                <option value="all">All Investigations</option>
                {availableCases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.id} ({c.title})
                  </option>
                ))}
              </select>
            </div>

            {/* Type Filter */}
            <div className="flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-[var(--text-muted)]" />
              <span className="text-xs text-[var(--text-muted)]">Type:</span>
              <div className="flex items-center p-0.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
                {[
                  { value: 'all', label: 'All' },
                  { value: 'executive', label: 'Executive' },
                  { value: 'detailed', label: 'Detailed' },
                ].map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    onClick={() => setTypeFilter(opt.value)}
                    className={`px-2.5 py-1 text-[11px] font-medium rounded-md transition-all ${
                      typeFilter === opt.value
                        ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-xs'
                        : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            <Button
              variant="ghost"
              size="sm"
              icon={RefreshCw}
              loading={isLoading}
              onClick={() => fetchReportsList(true)}
            >
              Refresh
            </Button>
          </div>
        </div>
      </Card>

      {/* Reports Catalog Table */}
      <Card
        title="Reports Archive"
        subtitle={`Displaying ${filteredReports.length} of ${totalCount} compiled forensic reports`}
        headerIcon={FileText}
        bodyClassName="p-0"
      >
        {isLoading ? (
          <div className="py-16 flex flex-col items-center justify-center gap-3 text-xs text-[var(--text-muted)]">
            <LoadingSpinner size="md" />
            <span>Scanning reports vault...</span>
          </div>
        ) : fetchError ? (
          <div className="p-8 text-center space-y-3">
            <AlertTriangle className="w-8 h-8 text-[var(--status-high)] mx-auto" />
            <p className="text-sm text-[var(--text-primary)] font-semibold">{fetchError}</p>
            <Button variant="secondary" size="sm" onClick={() => fetchReportsList(true)}>
              Retry Connection
            </Button>
          </div>
        ) : filteredReports.length === 0 ? (
          <EmptyState
            icon={FileText}
            title="No Generated Reports Found"
            description={
              searchQuery || typeFilter !== 'all' || caseFilter !== 'all'
                ? 'No reports match your active query filters.'
                : 'Compile your first structured PDF forensic report from an existing investigation.'
            }
            actionLabel="Generate Report"
            actionIcon={Plus}
            onAction={() => setIsGenerateModalOpen(true)}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[var(--bg-subtle)] border-b border-[var(--border-hairline)] text-[var(--text-muted)] uppercase tracking-wider font-mono text-[10px]">
                <tr>
                  <th className="px-5 py-3">Report ID</th>
                  <th className="px-4 py-3">Case Reference & Title</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Export SHA-256</th>
                  <th className="px-4 py-3">Size & Records</th>
                  <th className="px-4 py-3">Generated At</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F1F5F9]">
                {filteredReports.map((item) => (
                  <tr key={item.id} className="hover:bg-[var(--bg-subtle)] transition-colors">
                    <td className="px-5 py-3.5 font-mono font-bold text-[var(--text-primary)] whitespace-nowrap">
                      {item.id}
                    </td>

                    <td className="px-4 py-3.5 max-w-xs sm:max-w-sm">
                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => navigate(ROUTES.INVESTIGATIONS)}
                          className="font-mono text-[var(--accent-cobalt)] hover:underline font-semibold flex items-center gap-1"
                        >
                          <span>{item.investigation_id}</span>
                          <ExternalLink className="w-3 h-3 text-[var(--text-subtle)]" />
                        </button>
                      </div>
                      <div className="font-semibold text-[var(--text-primary)] truncate mt-0.5">
                        {item.title}
                      </div>
                    </td>

                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <Badge
                        variant={item.report_type === 'executive' ? 'low' : 'neutral'}
                        size="sm"
                      >
                        {item.report_type?.toUpperCase()}
                      </Badge>
                    </td>

                    <td className="px-4 py-3.5">
                      <div className="flex items-center gap-1.5 font-mono text-[11px]">
                        <span className="truncate max-w-[110px] text-[var(--text-primary)]" title={item.sha256}>
                          {item.sha256}
                        </span>
                        <button
                          type="button"
                          onClick={() => handleCopy(item.sha256, item.id)}
                          className="p-1 hover:bg-[#E2E8F0] rounded text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                          title="Copy full SHA-256 hash"
                        >
                          {copiedHash === item.id ? (
                            <Check className="w-3.5 h-3.5 text-[var(--status-low)]" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>

                    <td className="px-4 py-3.5 font-mono text-[var(--text-muted)] whitespace-nowrap">
                      <div>{formatBytes(item.file_size_bytes)}</div>
                      <div className="text-[10px] text-[var(--text-subtle)]">
                        {item.included_records?.length || 0} examination(s)
                      </div>
                    </td>

                    <td className="px-4 py-3.5 font-mono text-[var(--text-muted)] text-[11px] whitespace-nowrap">
                      {formatForensicDate(item.created_at)}
                    </td>

                    <td className="px-5 py-3.5 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        <Button
                          variant="secondary"
                          size="sm"
                          icon={Eye}
                          onClick={() => setPreviewReport(item)}
                          title="Preview PDF inside browser"
                        >
                          Preview
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          icon={Download}
                          onClick={() => window.open(getReportDownloadUrl(item.id), '_blank')}
                          title="Download PDF certificate"
                        >
                          Download
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* GENERATE REPORT MODAL */}
      <Modal
        isOpen={isGenerateModalOpen}
        onClose={() => setIsGenerateModalOpen(false)}
        title="Generate Forensic Report"
        subtitle="Compile an immutable, tamper-evident PDF inspection report from persistent case records."
        maxWidth="max-w-xl"
      >
        <form onSubmit={handleGenerateReport} className="space-y-4">
          {generateError && (
            <div className="p-3 rounded-lg bg-[var(--status-high-bg)] border border-[var(--status-high-border)] text-xs text-[var(--status-high)] flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{generateError}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">
              Select Investigation Case <span className="text-[var(--status-high)]">*</span>
            </label>
            {availableCases.length === 0 ? (
              <div className="text-xs text-[var(--text-muted)] p-3 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
                No investigations found. Please establish an investigation case in the Investigations section first.
              </div>
            ) : (
              <select
                required
                value={selectedCaseId}
                onChange={(e) => setSelectedCaseId(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] border border-[var(--border-strong)] rounded-lg focus:outline-none focus:border-[#2563EB]"
              >
                {availableCases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.id} — {c.title} ({c.investigator || 'Unassigned'})
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Report Type Selector */}
          <div>
            <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1.5">
              Report Format Type
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div
                onClick={() => setSelectedReportType('detailed')}
                className={`p-3 rounded-xl border text-left cursor-pointer transition-all ${
                  selectedReportType === 'detailed'
                    ? 'border-[#2563EB] bg-[var(--accent-subtle)]'
                    : 'border-[var(--border-hairline)] bg-[var(--bg-subtle)] hover:bg-[var(--bg-surface)]'
                }`}
              >
                <div className="text-xs font-bold text-[var(--text-primary)]">Detailed Forensic Report</div>
                <div className="text-[11px] text-[var(--text-muted)] mt-0.5 leading-relaxed">
                  Full bitstream dissection, byte offsets, object IDs, visual artifact references, and complete audit trail.
                </div>
              </div>

              <div
                onClick={() => setSelectedReportType('executive')}
                className={`p-3 rounded-xl border text-left cursor-pointer transition-all ${
                  selectedReportType === 'executive'
                    ? 'border-[#2563EB] bg-[var(--accent-subtle)]'
                    : 'border-[var(--border-hairline)] bg-[var(--bg-subtle)] hover:bg-[var(--bg-surface)]'
                }`}
              >
                <div className="text-xs font-bold text-[var(--text-primary)]">Executive Summary Brief</div>
                <div className="text-[11px] text-[var(--text-muted)] mt-0.5 leading-relaxed">
                  Concise 2–3 page risk overview, primary anomalies, and executive remediation recommendations.
                </div>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">
              Custom Report Title (Optional)
            </label>
            <input
              type="text"
              value={customTitle}
              onChange={(e) => setCustomTitle(e.target.value)}
              placeholder="Leave blank to use default case title"
              className="w-full px-3 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] placeholder-[#94A3B8] border border-[var(--border-strong)] rounded-lg focus:outline-none focus:border-[#2563EB]"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">
              Examiner Name / Attribution
            </label>
            <input
              type="text"
              value={examinerName}
              onChange={(e) => setExaminerName(e.target.value)}
              placeholder="e.g. Detective R. Kumar"
              className="w-full px-3 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] placeholder-[#94A3B8] border border-[var(--border-strong)] rounded-lg focus:outline-none focus:border-[#2563EB]"
            />
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-[var(--border-hairline)]">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setIsGenerateModalOpen(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="accent"
              size="sm"
              loading={isGenerating}
              disabled={availableCases.length === 0}
            >
              Generate Forensic PDF
            </Button>
          </div>
        </form>
      </Modal>

      {/* PDF PREVIEW MODAL */}
      <Modal
        isOpen={Boolean(previewReport)}
        onClose={() => setPreviewReport(null)}
        title={previewReport ? `${previewReport.id} — ${previewReport.title}` : 'Report Preview'}
        subtitle={previewReport ? `Case: ${previewReport.investigation_id} • SHA-256: ${previewReport.sha256?.substring(0, 16)}...` : ''}
        maxWidth="max-w-5xl"
      >
        {previewReport && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)] text-xs">
              <div className="flex items-center gap-2 font-mono text-[11px] truncate">
                <span className="font-semibold text-[var(--text-muted)]">SHA-256:</span>
                <span className="text-[var(--text-primary)] truncate">{previewReport.sha256}</span>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  icon={copiedHash === previewReport.id ? Check : Copy}
                  onClick={() => handleCopy(previewReport.sha256, previewReport.id)}
                >
                  {copiedHash === previewReport.id ? 'Copied' : 'Copy Hash'}
                </Button>
                <Button
                  variant="accent"
                  size="sm"
                  icon={Download}
                  onClick={() => window.open(getReportDownloadUrl(previewReport.id), '_blank')}
                >
                  Download PDF
                </Button>
              </div>
            </div>

            <div className="w-full h-[620px] rounded-xl overflow-hidden border border-[var(--border-strong)] bg-[var(--bg-subtle)]">
              <iframe
                src={getReportPreviewUrl(previewReport.id)}
                title="Forensic PDF Preview"
                className="w-full h-full border-0"
              />
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
