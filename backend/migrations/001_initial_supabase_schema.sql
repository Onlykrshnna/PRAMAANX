-- ==============================================================================
-- PRAMAANX - Initial Supabase PostgreSQL Schema Migration
-- ==============================================================================
-- File: backend/migrations/001_initial_supabase_schema.sql
-- Description: Core forensic relational tables, JSONB columns, TIMESTAMPTZ,
--              composite foreign key consistency, and Row Level Security (RLS).
-- Execution: Idempotent (safe to re-run). Does not drop or delete existing data.
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- 1. Investigations Table (Cases)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    investigator TEXT DEFAULT 'Analyst',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tags JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);
CREATE INDEX IF NOT EXISTS idx_investigations_created ON investigations(created_at);
CREATE INDEX IF NOT EXISTS idx_investigations_tags_gin ON investigations USING gin(tags);

-- ------------------------------------------------------------------------------
-- 2. Evidence Items Table (Specimens)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS evidence_items (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    original_filename TEXT NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    sha256 TEXT NOT NULL,
    detected_mime TEXT NOT NULL,
    detected_ext TEXT NOT NULL,
    stored_filename TEXT NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    integrity_status TEXT DEFAULT 'verified',
    last_verified_at TIMESTAMPTZ,
    storage_bucket TEXT DEFAULT 'pramaanx_evidence',
    storage_path TEXT,
    CONSTRAINT uq_evidence_investigation UNIQUE (id, investigation_id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON evidence_items(investigation_id);
CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence_items(sha256);

-- ------------------------------------------------------------------------------
-- 3. Analysis Records Table (Historical examinations)
-- ------------------------------------------------------------------------------
-- Composite foreign key enforces that analysis_records.investigation_id MUST match
-- the exact investigation_id of the referenced evidence_items record.
CREATE TABLE IF NOT EXISTS analysis_records (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL,
    analyzed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    analyzer_version TEXT NOT NULL DEFAULT '2.0.0',
    risk_score INTEGER NOT NULL,
    risk_category TEXT NOT NULL,
    entropy DOUBLE PRECISION NOT NULL,
    findings_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata_timeline_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    visual_evidence_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    plain_summary TEXT DEFAULT '',
    CONSTRAINT fk_analysis_evidence_investigation 
        FOREIGN KEY (evidence_id, investigation_id) 
        REFERENCES evidence_items(id, investigation_id) 
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analysis_investigation ON analysis_records(investigation_id);
CREATE INDEX IF NOT EXISTS idx_analysis_evidence ON analysis_records(evidence_id);
CREATE INDEX IF NOT EXISTS idx_analysis_risk ON analysis_records(risk_score);
CREATE INDEX IF NOT EXISTS idx_analysis_findings_gin ON analysis_records USING gin(findings_json);

-- ------------------------------------------------------------------------------
-- 4. Audit Trail Table (Immutable activity log)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    investigation_id TEXT REFERENCES investigations(id) ON DELETE SET NULL,
    evidence_id TEXT REFERENCES evidence_items(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor TEXT DEFAULT 'Analyst',
    details_json JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_investigation ON audit_logs(investigation_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);

-- ------------------------------------------------------------------------------
-- 5. Forensic Reports Table
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    report_type TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT DEFAULT '',
    sha256 TEXT NOT NULL,
    file_size_bytes BIGINT NOT NULL,
    stored_filename TEXT NOT NULL,
    included_records_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    generated_by TEXT DEFAULT 'Forensic Analyst',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    storage_bucket TEXT DEFAULT 'pramaanx_artifacts',
    storage_path TEXT
);

CREATE INDEX IF NOT EXISTS idx_reports_investigation ON reports(investigation_id);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at);

-- ------------------------------------------------------------------------------
-- 6. Row Level Security (RLS) Configuration
-- ------------------------------------------------------------------------------
-- Enable RLS on all public application tables to block direct unauthenticated
-- access through Supabase PostgREST public HTTP APIs.
ALTER TABLE investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;

-- Explicitly allow full access to the privileged service_role (used by server-side FastAPI backend)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'service_role_investigations' AND tablename = 'investigations') THEN
        CREATE POLICY "service_role_investigations" ON investigations FOR ALL TO service_role USING (true) WITH CHECK (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'service_role_evidence' AND tablename = 'evidence_items') THEN
        CREATE POLICY "service_role_evidence" ON evidence_items FOR ALL TO service_role USING (true) WITH CHECK (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'service_role_analysis' AND tablename = 'analysis_records') THEN
        CREATE POLICY "service_role_analysis" ON analysis_records FOR ALL TO service_role USING (true) WITH CHECK (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'service_role_audit' AND tablename = 'audit_logs') THEN
        CREATE POLICY "service_role_audit" ON audit_logs FOR ALL TO service_role USING (true) WITH CHECK (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'service_role_reports' AND tablename = 'reports') THEN
        CREATE POLICY "service_role_reports" ON reports FOR ALL TO service_role USING (true) WITH CHECK (true);
    END IF;
END $$;
