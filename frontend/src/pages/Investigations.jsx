/**
 * PRAMAANX - Investigations Management Page (Light SaaS Theme - Milestone D)
 * Persistent digital forensics case manager with evidence association,
 * cryptographic integrity checking, and auditable activity history.
 */

import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import PageHeader from '../components/layout/PageHeader';
import Card from '../components/common/Card';
import Badge from '../components/common/Badge';
import Button from '../components/common/Button';
import Modal from '../components/common/Modal';
import LoadingSpinner from '../components/common/LoadingSpinner';
import EmptyState from '../components/common/EmptyState';
import {
  FolderArchive,
  Search,
  Filter,
  Plus,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Download,
  Copy,
  Check,
  RefreshCw,
  Clock,
  History,
  UploadCloud,
  ChevronRight,
  User,
  Hash,
  ExternalLink,
  FileText,
} from 'lucide-react';
import {
  getInvestigations,
  createInvestigation,
  getInvestigation,
  updateInvestigation,
  uploadEvidenceToCase,
  verifyEvidenceIntegrity,
  getEvidenceDownloadUrl,
  reanalyzeEvidence,
  getEvidenceAnalysisHistory,
} from '../services/api';
import { formatBytes, formatForensicDate } from '../utils/formatters';
import { ROUTES } from '../utils/constants';

const STATUS_OPTIONS = [
  { value: 'all', label: 'All Cases' },
  { value: 'open', label: 'Open' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'closed', label: 'Closed' },
  { value: 'archived', label: 'Archived' },
];

function getStatusBadge(status) {
  const s = String(status || '').toLowerCase();
  switch (s) {
    case 'open':
      return <Badge variant="neutral" dot size="sm">OPEN</Badge>;
    case 'in_progress':
      return <Badge variant="medium" dot size="sm">IN PROGRESS</Badge>;
    case 'closed':
      return <Badge variant="low" dot size="sm">CLOSED</Badge>;
    case 'archived':
      return <Badge variant="demo" size="sm">ARCHIVED</Badge>;
    default:
      return <Badge variant="neutral" size="sm">{status || 'UNKNOWN'}</Badge>;
  }
}

export default function Investigations() {
  const navigate = useNavigate();

  // List view state
  const [investigations, setInvestigations] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [statusFilter, setStatusFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);

  // Create Case Modal
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newInvestigator, setNewInvestigator] = useState('');
  const [newPriority, setNewPriority] = useState('medium');
  const [newTags, setNewTags] = useState('');
  const [isCreating, setIsCreating] = useState(false);
  const [createError, setCreateError] = useState(null);

  // Case Detail Drawer / Modal
  const [selectedCaseId, setSelectedCaseId] = useState(null);
  const [caseDetail, setCaseDetail] = useState(null);
  const [isDetailLoading, setIsDetailLoading] = useState(false);
  const [detailTab, setDetailTab] = useState('evidence'); // 'evidence' | 'audit'
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  // Evidence Actions State
  const [verifyingId, setVerifyingId] = useState(null);
  const [verificationFeedback, setVerificationFeedback] = useState({});
  const [reanalyzingId, setReanalyzingId] = useState(null);
  const [copiedHash, setCopiedHash] = useState(null);
  const [historyModalData, setHistoryModalData] = useState(null);
  const [isHistoryLoading, setIsHistoryLoading] = useState(false);

  // Direct Evidence Upload in Drawer
  const [isUploadingEvidence, setIsUploadingEvidence] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const fileInputRef = useRef(null);

  // Fetch Investigations list
  const fetchInvestigations = async (showLoading = true) => {
    if (showLoading) setIsLoading(true);
    setFetchError(null);
    try {
      const res = await getInvestigations({
        status: statusFilter === 'all' ? undefined : statusFilter,
        search: searchQuery.trim() || undefined,
      });
      setInvestigations(res.investigations || []);
      setTotalCount(res.total || 0);
    } catch (err) {
      setFetchError(err.message || 'Failed to load investigations from server.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    let ignore = false;
    const load = async () => {
      try {
        const res = await getInvestigations({
          status: statusFilter === 'all' ? undefined : statusFilter,
          search: searchQuery.trim() || undefined,
        });
        if (!ignore) {
          setInvestigations(res.investigations || []);
          setTotalCount(res.total || 0);
          setFetchError(null);
        }
      } catch (err) {
        if (!ignore) {
          setFetchError(err.message || 'Failed to load investigations from server.');
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
  }, [statusFilter, searchQuery]);

  // Load single case detail
  const loadCaseDetail = async (caseId) => {
    if (!caseId) return;
    setIsDetailLoading(true);
    try {
      const res = await getInvestigation(caseId);
      setCaseDetail(res);
    } catch (err) {
      alert(`Error loading case details: ${err.message}`);
    } finally {
      setIsDetailLoading(false);
    }
  };

  const handleOpenCase = (caseId) => {
    setSelectedCaseId(caseId);
    setVerificationFeedback({});
    setDetailTab('evidence');
    loadCaseDetail(caseId);
  };

  const handleCloseCase = () => {
    setSelectedCaseId(null);
    setCaseDetail(null);
    fetchInvestigations(false);
  };

  // Create Case
  const handleCreateCase = async (e) => {
    e.preventDefault();
    if (!newTitle.trim()) {
      setCreateError('Case Title is required.');
      return;
    }
    setIsCreating(true);
    setCreateError(null);
    try {
      const payload = {
        title: newTitle.trim(),
        description: newDescription.trim(),
        investigator: newInvestigator.trim() || 'Forensic Examiner',
        priority: newPriority,
        tags: newTags
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean),
      };
      const created = await createInvestigation(payload);
      setIsCreateModalOpen(false);
      setNewTitle('');
      setNewDescription('');
      setNewInvestigator('');
      setNewTags('');
      fetchInvestigations(false);
      handleOpenCase(created.id);
    } catch (err) {
      setCreateError(err.message || 'Failed to create investigation.');
    } finally {
      setIsCreating(false);
    }
  };

  // Update Status
  const handleStatusChange = async (newStatus) => {
    if (!caseDetail?.case?.id || isUpdatingStatus) return;
    setIsUpdatingStatus(true);
    try {
      await updateInvestigation(caseDetail.case.id, { status: newStatus });
      await loadCaseDetail(caseDetail.case.id);
    } catch (err) {
      alert(`Status update failed: ${err.message}`);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  // Upload Evidence to Selected Case
  const handleEvidenceFileChange = async (e) => {
    const file = e.target.files?.[0];
    if (!file || !caseDetail?.case?.id) return;
    setIsUploadingEvidence(true);
    setUploadError(null);
    try {
      await uploadEvidenceToCase(caseDetail.case.id, file);
      await loadCaseDetail(caseDetail.case.id);
      if (fileInputRef.current) fileInputRef.current.value = '';
    } catch (err) {
      setUploadError(err.message || 'Evidence upload failed.');
    } finally {
      setIsUploadingEvidence(false);
    }
  };

  // Verify Evidence Integrity
  const handleVerifyIntegrity = async (evidenceId) => {
    setVerifyingId(evidenceId);
    try {
      const res = await verifyEvidenceIntegrity(evidenceId);
      setVerificationFeedback((prev) => ({
        ...prev,
        [evidenceId]: {
          status: res.status,
          message: res.message,
          match: res.match,
        },
      }));
      await loadCaseDetail(caseDetail.case.id);
    } catch (err) {
      alert(`Integrity verification failed: ${err.message}`);
    } finally {
      setVerifyingId(null);
    }
  };

  // Re-Analyze Evidence
  const handleReanalyze = async (evidenceId) => {
    if (!caseDetail?.case?.id || reanalyzingId) return;
    if (!confirm('Re-analyzing will execute the full forensic pipeline and record a new examination milestone without overwriting historical records. Proceed?')) {
      return;
    }
    setReanalyzingId(evidenceId);
    try {
      const res = await reanalyzeEvidence(caseDetail.case.id, evidenceId);
      alert(`Re-analysis complete! New examination record created with risk score: ${res.analysis.risk_score}/100.`);
      await loadCaseDetail(caseDetail.case.id);
    } catch (err) {
      alert(`Re-analysis failed: ${err.message}`);
    } finally {
      setReanalyzingId(null);
    }
  };

  // View Analysis Record
  const handleViewAnalysis = (record, filename) => {
    let pipelineData = null;
    try {
      pipelineData = typeof record.analysis_data === 'string'
        ? JSON.parse(record.analysis_data)
        : record.analysis_data;
    } catch (e) {
      console.error(e);
    }

    if (!pipelineData) {
      alert('Analysis record details could not be parsed.');
      return;
    }

    navigate(ROUTES.RESULTS, {
      state: {
        result: {
          file: {
            name: filename,
            type: pipelineData.file_type || 'evidence',
            size: 0,
            sha256: pipelineData.file_sha256 || '',
          },
          analysis: pipelineData,
        },
        type: 'single',
      },
    });
  };

  // Load Analysis History
  const handleViewHistory = async (evidence) => {
    setIsHistoryLoading(true);
    setHistoryModalData({ evidence, records: [] });
    try {
      const res = await getEvidenceAnalysisHistory(caseDetail.case.id, evidence.id);
      setHistoryModalData({ evidence, records: res.records || [] });
    } catch (err) {
      alert(`Failed to load history: ${err.message}`);
      setHistoryModalData(null);
    } finally {
      setIsHistoryLoading(false);
    }
  };

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      <PageHeader
        title="Forensic Investigations"
        subtitle="Auditable digital forensic cases, immutable evidence vault tracking, and examination history."
        actions={
          <Button
            variant="accent"
            icon={Plus}
            onClick={() => setIsCreateModalOpen(true)}
          >
            New Investigation
          </Button>
        }
      />

      {/* Summary Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card bodyClassName="p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-strong)] flex items-center justify-center text-[var(--text-primary)]">
            <FolderArchive className="w-5 h-5 text-[var(--accent-cobalt)]" />
          </div>
          <div>
            <div className="text-xl font-bold text-[var(--text-primary)]">{totalCount}</div>
            <div className="text-xs text-[var(--text-muted)]">Total Investigations</div>
          </div>
        </Card>

        <Card bodyClassName="p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[var(--status-low-bg)] border border-[var(--status-low-border)] flex items-center justify-center text-[var(--status-low)]">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xl font-bold text-[var(--text-primary)]">
              {investigations.filter((i) => i.status === 'open' || i.status === 'in_progress').length}
            </div>
            <div className="text-xs text-[var(--text-muted)]">Active Cases</div>
          </div>
        </Card>

        <Card bodyClassName="p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[var(--status-medium-bg)] border border-[var(--status-medium-border)] flex items-center justify-center text-[var(--status-medium)]">
            <Hash className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xl font-bold text-[var(--text-primary)]">
              {investigations.reduce((acc, curr) => acc + (curr.evidence_count || 0), 0)}
            </div>
            <div className="text-xs text-[var(--text-muted)]">Vault Evidence Items</div>
          </div>
        </Card>

        <Card bodyClassName="p-4 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-strong)] flex items-center justify-center text-[var(--text-secondary)]">
            <Clock className="w-5 h-5" />
          </div>
          <div>
            <div className="text-xl font-bold text-[var(--text-primary)]">
              {investigations.filter((i) => i.status === 'closed' || i.status === 'archived').length}
            </div>
            <div className="text-xs text-[var(--text-muted)]">Resolved / Archived</div>
          </div>
        </Card>
      </div>

      {/* Filter and Search Bar */}
      <Card bodyClassName="p-4">
        <div className="flex flex-col sm:flex-row gap-3 items-center justify-between">
          <div className="relative w-full sm:w-96">
            <Search className="absolute left-3 top-2.5 w-4 h-4 text-[var(--text-muted)]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by case ID, title, investigator, or tags..."
              className="w-full pl-9 pr-4 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] placeholder-[#94A3B8] border border-[var(--border-hairline)] rounded-lg focus:outline-none focus:border-[#2563EB]"
            />
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto overflow-x-auto">
            <Filter className="w-3.5 h-3.5 text-[var(--text-muted)] shrink-0" />
            <span className="text-xs text-[var(--text-muted)] shrink-0">Status:</span>
            <div className="flex items-center p-0.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
              {STATUS_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setStatusFilter(opt.value)}
                  className={`px-2.5 py-1 text-[11px] font-medium rounded-md transition-all whitespace-nowrap ${
                    statusFilter === opt.value
                      ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-xs'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </Card>

      {/* Cases Registry Table */}
      <Card
        title="Case Registry"
        subtitle={`Displaying ${investigations.length} recorded forensic investigation cases`}
        headerIcon={FolderArchive}
        bodyClassName="p-0"
        action={
          <Button
            variant="ghost"
            size="sm"
            icon={RefreshCw}
            loading={isLoading}
            onClick={() => fetchInvestigations(true)}
          >
            Refresh
          </Button>
        }
      >
        {isLoading ? (
          <div className="py-16 flex flex-col items-center justify-center gap-3 text-xs text-[var(--text-muted)]">
            <LoadingSpinner size="md" />
            <span>Loading cases from persistent database...</span>
          </div>
        ) : fetchError ? (
          <div className="p-8 text-center space-y-3">
            <AlertTriangle className="w-8 h-8 text-[var(--status-high)] mx-auto" />
            <p className="text-sm text-[var(--text-primary)] font-semibold">{fetchError}</p>
            <Button variant="secondary" size="sm" onClick={() => fetchInvestigations(true)}>
              Retry Connection
            </Button>
          </div>
        ) : investigations.length === 0 ? (
          <EmptyState
            icon={FolderArchive}
            title="No Investigations Found"
            description={
              searchQuery || statusFilter !== 'all'
                ? 'No cases match your active search and status filter.'
                : 'Create your first forensic case to organize evidence items, preserve cryptographic integrity, and maintain auditable analysis records.'
            }
            actionLabel="Create Investigation"
            actionIcon={Plus}
            onAction={() => setIsCreateModalOpen(true)}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[var(--bg-subtle)] border-b border-[var(--border-hairline)] text-[var(--text-muted)] uppercase tracking-wider font-mono text-[10px]">
                <tr>
                  <th className="px-5 py-3">Case ID</th>
                  <th className="px-4 py-3">Title & Details</th>
                  <th className="px-4 py-3">Investigator</th>
                  <th className="px-4 py-3">Evidence</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-5 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F1F5F9]">
                {investigations.map((item) => (
                  <tr
                    key={item.id}
                    className="hover:bg-[var(--bg-subtle)] transition-colors cursor-pointer group"
                    onClick={() => handleOpenCase(item.id)}
                  >
                    <td className="px-5 py-3.5 font-mono font-semibold text-[var(--text-primary)] whitespace-nowrap">
                      <span className="text-[var(--accent-cobalt)] group-hover:underline">{item.id}</span>
                    </td>
                    <td className="px-4 py-3.5 max-w-xs sm:max-w-md">
                      <div className="font-semibold text-[var(--text-primary)] truncate">{item.title}</div>
                      {item.description && (
                        <div className="text-[11px] text-[var(--text-muted)] truncate mt-0.5">
                          {item.description}
                        </div>
                      )}
                      {item.tags && (
                        <div className="flex flex-wrap gap-1 mt-1">
                          {item.tags.split(',').filter(Boolean).map((t, i) => (
                            <span
                              key={i}
                              className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[var(--bg-subtle)] text-[var(--text-secondary)] border border-[var(--border-hairline)]"
                            >
                              #{t.trim()}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3.5 text-[var(--text-muted)] whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <User className="w-3.5 h-3.5 text-[var(--text-subtle)]" />
                        <span>{item.investigator || 'Unassigned'}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <span className="font-mono px-2 py-0.5 rounded-full text-[11px] font-semibold bg-[var(--bg-subtle)] text-[var(--text-primary)] border border-[var(--border-hairline)]">
                        {item.evidence_count || 0} file{item.evidence_count === 1 ? '' : 's'}
                      </span>
                    </td>
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      {getStatusBadge(item.status)}
                    </td>
                    <td className="px-4 py-3.5 font-mono text-[var(--text-muted)] text-[11px] whitespace-nowrap">
                      {formatForensicDate(item.created_at)}
                    </td>
                    <td className="px-5 py-3.5 text-right whitespace-nowrap">
                      <Button
                        variant="ghost"
                        size="sm"
                        icon={ChevronRight}
                        onClick={(e) => {
                          e.stopPropagation();
                          handleOpenCase(item.id);
                        }}
                      >
                        Inspect
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* CREATE INVESTIGATION MODAL */}
      <Modal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        title="Create Forensic Investigation"
        subtitle="Establish a new case to associate digital evidence files and track cryptographic verification."
      >
        <form onSubmit={handleCreateCase} className="space-y-4">
          {createError && (
            <div className="p-3 rounded-lg bg-[var(--status-high-bg)] border border-[var(--status-high-border)] text-xs text-[var(--status-high)] flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{createError}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">
              Case Title <span className="text-[var(--status-high)]">*</span>
            </label>
            <input
              type="text"
              required
              autoFocus
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="e.g. Executive Payroll Alteration Inquiry"
              className="w-full px-3 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] placeholder-[#94A3B8] border border-[var(--border-strong)] rounded-lg focus:outline-none focus:border-[#2563EB]"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">
              Description & Objective
            </label>
            <textarea
              rows={3}
              value={newDescription}
              onChange={(e) => setNewDescription(e.target.value)}
              placeholder="Summary of suspected manipulation, context, or scope of digital inspection..."
              className="w-full px-3 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] placeholder-[#94A3B8] border border-[var(--border-strong)] rounded-lg focus:outline-none focus:border-[#2563EB]"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">
                Lead Investigator
              </label>
              <input
                type="text"
                value={newInvestigator}
                onChange={(e) => setNewInvestigator(e.target.value)}
                placeholder="e.g. Detective R. Kumar"
                className="w-full px-3 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] placeholder-[#94A3B8] border border-[var(--border-strong)] rounded-lg focus:outline-none focus:border-[#2563EB]"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">
                Priority
              </label>
              <select
                value={newPriority}
                onChange={(e) => setNewPriority(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] border border-[var(--border-strong)] rounded-lg focus:outline-none focus:border-[#2563EB]"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-[var(--text-primary)] mb-1">
              Case Tags (comma-separated)
            </label>
            <input
              type="text"
              value={newTags}
              onChange={(e) => setNewTags(e.target.value)}
              placeholder="e.g. invoice, pdf-structure, financial"
              className="w-full px-3 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] placeholder-[#94A3B8] border border-[var(--border-strong)] rounded-lg focus:outline-none focus:border-[#2563EB]"
            />
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-[var(--border-hairline)]">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setIsCreateModalOpen(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="accent"
              size="sm"
              loading={isCreating}
            >
              Create Case
            </Button>
          </div>
        </form>
      </Modal>

      {/* CASE DETAIL DRAWER / MODAL */}
      <Modal
        isOpen={Boolean(selectedCaseId)}
        onClose={handleCloseCase}
        title={caseDetail?.case ? `${caseDetail.case.id} — ${caseDetail.case.title}` : 'Case Investigation'}
        subtitle={caseDetail?.case ? `Lead Investigator: ${caseDetail.case.investigator || 'Unassigned'} • Created ${formatForensicDate(caseDetail.case.created_at)}` : ''}
        maxWidth="max-w-4xl"
      >
        {isDetailLoading || !caseDetail ? (
          <div className="py-16 flex flex-col items-center justify-center gap-3 text-xs text-[var(--text-muted)]">
            <LoadingSpinner size="md" />
            <span>Loading case dossier from persistent vault...</span>
          </div>
        ) : (
          <div className="space-y-6">
            {/* Header Status & Control Bar */}
            <div className="p-3.5 rounded-xl bg-[var(--bg-subtle)] border border-[var(--border-hairline)] flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-[var(--text-primary)]">Case Status:</span>
                <select
                  disabled={isUpdatingStatus}
                  value={caseDetail.case.status}
                  onChange={(e) => handleStatusChange(e.target.value)}
                  className="px-2.5 py-1 text-xs font-semibold bg-[var(--bg-surface)] text-[var(--text-primary)] border border-[var(--border-strong)] rounded-lg focus:outline-none focus:border-[#2563EB]"
                >
                  <option value="open">Open</option>
                  <option value="in_progress">In Progress</option>
                  <option value="closed">Closed</option>
                  <option value="archived">Archived</option>
                </select>
                {isUpdatingStatus && <LoadingSpinner size="sm" />}
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setDetailTab('evidence')}
                  className={`px-3 py-1 text-xs font-semibold rounded-lg transition-all ${
                    detailTab === 'evidence'
                      ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-xs border border-[var(--border-strong)]'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  Evidence Vault ({caseDetail.evidence?.length || 0})
                </button>
                <button
                  type="button"
                  onClick={() => setDetailTab('audit')}
                  className={`px-3 py-1 text-xs font-semibold rounded-lg transition-all ${
                    detailTab === 'audit'
                      ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-xs border border-[var(--border-strong)]'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  Audit Trail ({caseDetail.audit_logs?.length || 0})
                </button>

                <Button
                  variant="outline"
                  size="sm"
                  icon={FileText}
                  onClick={() => navigate(ROUTES.REPORTS)}
                >
                  Reports
                </Button>
              </div>
            </div>

            {/* Case Description & Metadata */}
            {caseDetail.case.description && (
              <div className="text-xs text-[var(--text-secondary)] bg-[var(--bg-surface)] p-3 rounded-lg border border-[var(--border-hairline)] leading-relaxed">
                <span className="font-semibold text-[var(--text-primary)]">Investigation Objective: </span>
                {caseDetail.case.description}
              </div>
            )}

            {/* TAB 1: EVIDENCE VAULT */}
            {detailTab === 'evidence' && (
              <div className="space-y-4">
                {/* Direct File Ingestion into Case */}
                <div className="p-4 rounded-xl border border-dashed border-[var(--border-strong)] bg-[var(--bg-subtle)] flex flex-col sm:flex-row items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-[var(--bg-surface)] border border-[var(--border-strong)] flex items-center justify-center text-[var(--accent-cobalt)]">
                      <UploadCloud className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="text-xs font-bold text-[var(--text-primary)]">
                        Acquire Evidence into this Case
                      </div>
                      <div className="text-[11px] text-[var(--text-muted)]">
                        Files are stored in the read-only vault with automatic SHA-256 baseline calculation and pipeline screening.
                      </div>
                    </div>
                  </div>

                  <div className="shrink-0">
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleEvidenceFileChange}
                      className="hidden"
                      id="evidence-file-input"
                    />
                    <Button
                      variant="primary"
                      size="sm"
                      icon={UploadCloud}
                      loading={isUploadingEvidence}
                      onClick={() => fileInputRef.current?.click()}
                    >
                      Ingest Evidence File
                    </Button>
                  </div>
                </div>

                {uploadError && (
                  <div className="p-3 rounded-lg bg-[var(--status-high-bg)] border border-[var(--status-high-border)] text-xs text-[var(--status-high)] flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>{uploadError}</span>
                  </div>
                )}

                {/* Evidence Items List */}
                {caseDetail.evidence?.length === 0 ? (
                  <div className="py-10 text-center border rounded-xl border-[var(--border-hairline)] bg-[var(--bg-surface)]">
                    <FolderArchive className="w-8 h-8 text-[var(--text-subtle)] mx-auto mb-2" />
                    <p className="text-xs font-semibold text-[var(--text-primary)]">No Evidence Acquired Yet</p>
                    <p className="text-[11px] text-[var(--text-muted)] mt-0.5">
                      Use the button above to upload files or associate existing analyses.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {caseDetail.evidence.map((ev) => {
                      const feedback = verificationFeedback[ev.id];
                      const isVerifying = verifyingId === ev.id;
                      const isReanalyzing = reanalyzingId === ev.id;

                      return (
                        <div
                          key={ev.id}
                          className="p-4 rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)] space-y-3 shadow-xs hover:border-[var(--border-strong)] transition-all"
                        >
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-xs font-bold text-[var(--text-primary)]">{ev.filename}</span>
                                <Badge variant="neutral" size="sm">
                                  {ev.file_format?.toUpperCase() || 'FILE'}
                                </Badge>
                                <span className="text-[11px] font-mono text-[var(--text-muted)]">
                                  {formatBytes(ev.file_size)}
                                </span>
                              </div>
                              <div className="text-[11px] text-[var(--text-muted)] font-mono mt-0.5 flex items-center gap-1.5">
                                <span>Acquired: {formatForensicDate(ev.acquired_at)}</span>
                              </div>
                            </div>

                            {/* Integrity Badge */}
                            <div className="flex items-center gap-2">
                              {ev.integrity_status === 'verified' && (
                                <Badge variant="low" dot size="sm">
                                  INTEGRITY VERIFIED
                                </Badge>
                              )}
                              {ev.integrity_status === 'tampered' && (
                                <Badge variant="high" dot size="sm">
                                  TAMPERING DETECTED
                                </Badge>
                              )}
                              {ev.integrity_status === 'unverified' && (
                                <Badge variant="neutral" size="sm">
                                  UNVERIFIED
                                </Badge>
                              )}
                            </div>
                          </div>

                          {/* Cryptographic Hash */}
                          <div className="p-2.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)] flex items-center justify-between gap-2 text-xs">
                            <div className="flex items-center gap-2 font-mono truncate text-[11px]">
                              <span className="font-semibold text-[var(--text-muted)] text-[10px]">SHA-256:</span>
                              <span className="text-[var(--text-primary)] truncate">{ev.sha256_hash}</span>
                            </div>
                            <Button
                              variant="ghost"
                              size="sm"
                              icon={copiedHash === ev.id ? Check : Copy}
                              onClick={() => copyToClipboard(ev.sha256_hash, ev.id)}
                            >
                              {copiedHash === ev.id ? 'Copied' : 'Copy'}
                            </Button>
                          </div>

                          {/* Verification Alert Feedback */}
                          {feedback && (
                            <div
                              className={`p-2.5 rounded-lg text-xs font-mono flex items-center gap-2 ${
                                feedback.match
                                  ? 'bg-[var(--status-low-bg)] text-[var(--status-low)] border border-[var(--status-low-border)]'
                                  : 'bg-[var(--status-high-bg)] text-[var(--status-high)] border border-[var(--status-high-border)]'
                              }`}
                            >
                              {feedback.match ? <ShieldCheck className="w-4 h-4 shrink-0" /> : <ShieldAlert className="w-4 h-4 shrink-0" />}
                              <span>{feedback.message}</span>
                            </div>
                          )}

                          {/* Action Toolbar */}
                          <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-[var(--border-hairline)]">
                            <div className="flex items-center gap-2">
                              <Button
                                variant="secondary"
                                size="sm"
                                icon={ShieldCheck}
                                loading={isVerifying}
                                onClick={() => handleVerifyIntegrity(ev.id)}
                              >
                                Verify SHA-256
                              </Button>

                              <Button
                                variant="secondary"
                                size="sm"
                                icon={Download}
                                onClick={() => window.open(getEvidenceDownloadUrl(ev.id), '_blank')}
                              >
                                Download Pristine
                              </Button>

                              <Button
                                variant="ghost"
                                size="sm"
                                icon={History}
                                onClick={() => handleViewHistory(ev)}
                              >
                                Examination History
                              </Button>
                            </div>

                            <Button
                              variant="outline"
                              size="sm"
                              icon={RefreshCw}
                              loading={isReanalyzing}
                              onClick={() => handleReanalyze(ev.id)}
                            >
                              Re-Analyze
                            </Button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* TAB 2: AUDIT ACTIVITY TRAIL */}
            {detailTab === 'audit' && (
              <div className="space-y-3">
                <div className="text-xs text-[var(--text-muted)]">
                  Cryptographically traceable activity log recording all evidence acquisitions, verification runs, and status transitions for this case.
                </div>

                <div className="border rounded-xl border-[var(--border-hairline)] bg-[var(--bg-surface)] divide-y divide-[#F1F5F9]">
                  {caseDetail.audit_logs?.length === 0 ? (
                    <div className="p-8 text-center text-xs text-[var(--text-muted)]">
                      No audit events recorded for this case.
                    </div>
                  ) : (
                    caseDetail.audit_logs.map((log) => (
                      <div key={log.id} className="p-3 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-[var(--text-primary)] font-mono uppercase tracking-wider text-[11px]">
                              {log.action.replace(/_/g, ' ')}
                            </span>
                            <span className="text-[11px] text-[var(--text-muted)]">by {log.actor}</span>
                          </div>
                          {log.details && (
                            <p className="text-[var(--text-secondary)] text-[11px] font-mono break-all">
                              {log.details}
                            </p>
                          )}
                        </div>
                        <div className="font-mono text-[var(--text-muted)] text-[10px] shrink-0">
                          {formatForensicDate(log.timestamp)}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </Modal>

      {/* ANALYSIS HISTORY MODAL */}
      <Modal
        isOpen={Boolean(historyModalData)}
        onClose={() => setHistoryModalData(null)}
        title="Examination Milestone History"
        subtitle={`Audit records for evidence: ${historyModalData?.evidence?.filename || ''}`}
        maxWidth="max-w-2xl"
      >
        {isHistoryLoading ? (
          <div className="py-12 flex flex-col items-center justify-center gap-2 text-xs text-[var(--text-muted)]">
            <LoadingSpinner size="md" />
            <span>Loading examination records...</span>
          </div>
        ) : historyModalData?.records?.length === 0 ? (
          <div className="py-8 text-center text-xs text-[var(--text-muted)]">
            No previous analysis records found for this evidence item.
          </div>
        ) : (
          <div className="space-y-3">
            {historyModalData?.records?.map((rec, idx) => (
              <div
                key={rec.id}
                className="p-3.5 rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-subtle)] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-[var(--text-primary)]">Run #{historyModalData.records.length - idx}</span>
                    <Badge variant={rec.risk_score >= 70 ? 'high' : rec.risk_score >= 31 ? 'medium' : 'low'} size="sm">
                      RISK {rec.risk_score}/100
                    </Badge>
                    <span className="font-mono text-[10px] text-[var(--text-muted)]">v{rec.analyzer_version}</span>
                  </div>
                  <div className="text-[11px] text-[var(--text-secondary)] mt-1 font-mono">
                    {rec.findings_summary || 'Analysis completed with zero high-severity anomalies.'}
                  </div>
                  <div className="text-[10px] text-[var(--text-muted)] mt-0.5 font-mono">
                    Executed: {formatForensicDate(rec.created_at)}
                  </div>
                </div>

                <Button
                  variant="secondary"
                  size="sm"
                  icon={ExternalLink}
                  onClick={() => handleViewAnalysis(rec, historyModalData.evidence.filename)}
                >
                  View Report
                </Button>
              </div>
            ))}
          </div>
        )}
      </Modal>
    </div>
  );
}
