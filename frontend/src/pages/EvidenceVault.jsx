/**
 * PRAMAANX - Evidence Vault Page (Light SaaS Theme - Milestone D)
 * Central immutable repository for acquired forensic evidence, cryptographic
 * SHA-256 integrity auditing, and computer vision artifacts (Grad-CAM & ELA maps).
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
  ShieldAlert,
  ShieldCheck,
  Eye,
  Cpu,
  Zap,
  Search,
  Filter,
  Download,
  Copy,
  Check,
  RefreshCw,
  AlertTriangle,
  Lock,
  ExternalLink,
} from 'lucide-react';
import {
  getEvidenceVaultItems,
  verifyEvidenceIntegrity,
  getEvidenceDownloadUrl,
} from '../services/api';
import { formatBytes, formatForensicDate } from '../utils/formatters';
import { ROUTES } from '../utils/constants';

export default function EvidenceVault() {
  const navigate = useNavigate();

  const [evidenceItems, setEvidenceItems] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [isLoading, setIsLoading] = useState(true);
  const [fetchError, setFetchError] = useState(null);

  const [copiedHash, setCopiedHash] = useState(null);
  const [verifyingId, setVerifyingId] = useState(null);
  const [verifyResults, setVerifyResults] = useState({});
  const [previewImage, setPreviewImage] = useState(null);

  const fetchEvidence = async (showLoading = true) => {
    if (showLoading) setIsLoading(true);
    setFetchError(null);
    try {
      const res = await getEvidenceVaultItems({
        search: searchQuery.trim() || undefined,
        status: statusFilter === 'all' ? undefined : statusFilter,
      });
      setEvidenceItems(res.evidence || []);
      setTotalCount(res.total || 0);
    } catch (err) {
      setFetchError(err.message || 'Failed to retrieve evidence from vault.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    let ignore = false;
    const load = async () => {
      try {
        const res = await getEvidenceVaultItems({
          search: searchQuery.trim() || undefined,
          status: statusFilter === 'all' ? undefined : statusFilter,
        });
        if (!ignore) {
          setEvidenceItems(res.evidence || []);
          setTotalCount(res.total || 0);
          setFetchError(null);
        }
      } catch (err) {
        if (!ignore) {
          setFetchError(err.message || 'Failed to retrieve evidence from vault.');
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
  }, [searchQuery, statusFilter]);

  const handleVerify = async (item) => {
    setVerifyingId(item.id);
    try {
      const res = await verifyEvidenceIntegrity(item.id);
      setVerifyResults((prev) => ({
        ...prev,
        [item.id]: {
          status: res.status,
          message: res.message,
          match: res.match,
        },
      }));
      await fetchEvidence(false);
    } catch (err) {
      alert(`Integrity verification failed: ${err.message}`);
    } finally {
      setVerifyingId(null);
    }
  };

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      <PageHeader
        title="Evidence Vault & Artifacts"
        subtitle="Immutable storage for ingested forensic evidence, on-demand cryptographic verification, and neural tamper artifacts."
        badge={
          <Badge variant="neutral" size="sm">
            READ-ONLY VAULT
          </Badge>
        }
        actions={
          <Button
            variant="secondary"
            size="sm"
            icon={RefreshCw}
            loading={isLoading}
            onClick={() => fetchEvidence(true)}
          >
            Refresh Vault
          </Button>
        }
      />

      {/* Methodology Explanations */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card
          title="Grad-CAM Saliency Maps"
          subtitle="Gradient-weighted Class Activation Mapping"
          headerIcon={Cpu}
        >
          <p className="text-xs text-[var(--text-muted)] leading-relaxed mb-3">
            Computes gradients off the final convolutional feature block of the EfficientNet-B0 model. Highlights spatial regions that most strongly swayed the neural classifier toward a tampering verdict.
          </p>
          <div className="p-2.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)] text-[11px] font-mono text-[var(--text-primary)]">
            Artifact Storage: backend/data/vault/artifacts/
          </div>
        </Card>

        <Card
          title="Error Level Analysis (ELA)"
          subtitle="JPEG Compression Differential Reconstruction"
          headerIcon={Zap}
        >
          <p className="text-xs text-[var(--text-muted)] leading-relaxed mb-3">
            Re-compresses images at a standardized 95% JPEG quality factor and calculates pixel Euclidean distance. Surfaces digital error differentials, exposing spliced foreign elements.
          </p>
          <div className="p-2.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)] text-[11px] font-mono text-[var(--text-primary)]">
            Tamper Detection: Pixel-level deviation analysis
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
              placeholder="Search by filename, SHA-256, or Case ID..."
              className="w-full pl-9 pr-4 py-2 text-xs bg-[var(--bg-subtle)] text-[var(--text-primary)] placeholder-[#94A3B8] border border-[var(--border-hairline)] rounded-lg focus:outline-none focus:border-[#2563EB]"
            />
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <Filter className="w-3.5 h-3.5 text-[var(--text-muted)]" />
            <span className="text-xs text-[var(--text-muted)]">Integrity:</span>
            <div className="flex items-center p-0.5 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)]">
              {[
                { value: 'all', label: 'All Items' },
                { value: 'verified', label: 'Verified' },
                { value: 'tampered', label: 'Tampered' },
                { value: 'unverified', label: 'Unverified' },
              ].map((opt) => (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => setStatusFilter(opt.value)}
                  className={`px-2.5 py-1 text-[11px] font-medium rounded-md transition-all ${
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

      {/* Vault Evidence Table */}
      <Card
        title="Evidence Inventory"
        subtitle={`Displaying ${evidenceItems.length} of ${totalCount} stored evidence artifacts in persistent vault`}
        headerIcon={Lock}
        bodyClassName="p-0"
      >
        {isLoading ? (
          <div className="py-16 flex flex-col items-center justify-center gap-3 text-xs text-[var(--text-muted)]">
            <LoadingSpinner size="md" />
            <span>Scanning evidence vault storage...</span>
          </div>
        ) : fetchError ? (
          <div className="p-8 text-center space-y-3">
            <AlertTriangle className="w-8 h-8 text-[var(--status-high)] mx-auto" />
            <p className="text-sm text-[var(--text-primary)] font-semibold">{fetchError}</p>
            <Button variant="secondary" size="sm" onClick={() => fetchEvidence(true)}>
              Retry Connection
            </Button>
          </div>
        ) : evidenceItems.length === 0 ? (
          <EmptyState
            icon={Eye}
            title="Evidence Vault is Empty"
            description={
              searchQuery || statusFilter !== 'all'
                ? 'No evidence matches your active query filter.'
                : 'Evidence files ingested into investigations will appear here with cryptographic hashes and on-demand verification.'
            }
            actionLabel="Start New Analysis"
            actionIcon={ShieldAlert}
            onAction={() => navigate(ROUTES.ANALYZE)}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[var(--bg-subtle)] border-b border-[var(--border-hairline)] text-[var(--text-muted)] uppercase tracking-wider font-mono text-[10px]">
                <tr>
                  <th className="px-5 py-3">Evidence Filename</th>
                  <th className="px-4 py-3">Associated Case</th>
                  <th className="px-4 py-3">Format & Size</th>
                  <th className="px-4 py-3">SHA-256 Digest</th>
                  <th className="px-4 py-3">Integrity State</th>
                  <th className="px-4 py-3">Acquired At</th>
                  <th className="px-5 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#F1F5F9]">
                {evidenceItems.map((item) => {
                  const isVerifying = verifyingId === item.id;
                  const verifyInfo = verifyResults[item.id];

                  return (
                    <tr key={item.id} className="hover:bg-[var(--bg-subtle)] transition-colors">
                      <td className="px-5 py-3.5">
                        <div className="font-semibold text-[var(--text-primary)]">{item.filename}</div>
                        <div className="text-[10px] text-[var(--text-muted)] font-mono mt-0.5">
                          ID: {item.id}
                        </div>
                      </td>

                      <td className="px-4 py-3.5">
                        <button
                          type="button"
                          onClick={() => navigate(ROUTES.INVESTIGATIONS)}
                          className="font-mono text-[var(--accent-cobalt)] hover:underline font-semibold flex items-center gap-1"
                        >
                          <span>{item.case_id}</span>
                          <ExternalLink className="w-3 h-3 text-[var(--text-subtle)]" />
                        </button>
                        {item.case_title && (
                          <div className="text-[11px] text-[var(--text-muted)] truncate max-w-[180px]">
                            {item.case_title}
                          </div>
                        )}
                      </td>

                      <td className="px-4 py-3.5 font-mono text-[var(--text-muted)]">
                        <span className="uppercase text-[var(--text-primary)] font-medium">
                          {item.file_format || 'FILE'}
                        </span>
                        {' • '}
                        {formatBytes(item.file_size)}
                      </td>

                      <td className="px-4 py-3.5">
                        <div className="flex items-center gap-1.5 font-mono text-[11px]">
                          <span className="truncate max-w-[120px] text-[var(--text-primary)]" title={item.sha256_hash}>
                            {item.sha256_hash}
                          </span>
                          <button
                            type="button"
                            onClick={() => handleCopy(item.sha256_hash, item.id)}
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

                      <td className="px-4 py-3.5">
                        <div className="space-y-1">
                          {item.integrity_status === 'verified' && (
                            <Badge variant="low" dot size="sm">
                              VERIFIED
                            </Badge>
                          )}
                          {item.integrity_status === 'tampered' && (
                            <Badge variant="high" dot size="sm">
                              TAMPERED
                            </Badge>
                          )}
                          {item.integrity_status === 'unverified' && (
                            <Badge variant="neutral" size="sm">
                              UNVERIFIED
                            </Badge>
                          )}
                          {verifyInfo && (
                            <div className="text-[10px] font-mono text-[var(--text-muted)]">
                              {verifyInfo.message}
                            </div>
                          )}
                        </div>
                      </td>

                      <td className="px-4 py-3.5 font-mono text-[var(--text-muted)] text-[11px] whitespace-nowrap">
                        {formatForensicDate(item.acquired_at)}
                      </td>

                      <td className="px-5 py-3.5 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5">
                          <Button
                            variant="secondary"
                            size="sm"
                            icon={ShieldCheck}
                            loading={isVerifying}
                            onClick={() => handleVerify(item)}
                            title="Recalculate SHA-256 against stored baseline"
                          >
                            Verify
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            icon={Download}
                            onClick={() => window.open(getEvidenceDownloadUrl(item.id), '_blank')}
                            title="Download original file from vault"
                          >
                            Download
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Visual Image Modal Lightbox */}
      <Modal
        isOpen={Boolean(previewImage)}
        onClose={() => setPreviewImage(null)}
        title={previewImage?.title || 'Visual Evidence Preview'}
        subtitle={previewImage?.subtitle || ''}
        maxWidth="max-w-3xl"
      >
        {previewImage && (
          <div className="space-y-3">
            <div className="bg-[#0F172A] rounded-xl overflow-hidden p-2 flex items-center justify-center">
              <img
                src={previewImage.url}
                alt="Evidence Artifact"
                className="max-h-[500px] w-auto object-contain rounded-lg"
              />
            </div>
            <div className="flex justify-between items-center text-xs text-[var(--text-muted)]">
              <span className="font-mono">{previewImage.filename}</span>
              <Button
                variant="secondary"
                size="sm"
                icon={Download}
                onClick={() => window.open(previewImage.url, '_blank')}
              >
                Download Map
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
