/**
 * PRAMAANX - Architectural Laboratory Footer
 * Minimal technical footer with laboratory disclosures, navigation links,
 * and cryptographic privacy notice.
 */

import { Link } from 'react-router-dom';
import { Lock } from 'lucide-react';
import { ROUTES, APP_NAME, APP_VERSION } from '../../utils/constants';
import logoImg from '../../assets/image.png';

export default function Footer() {
  return (
    <footer className="mt-auto border-t border-[var(--border-hairline)] bg-[var(--bg-surface)] text-xs text-[var(--text-muted)] transition-colors duration-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-8 items-start">
          {/* Column 1: Brand & Scientific Mission */}
          <div className="md:col-span-5 space-y-3">
            <div className="flex items-center gap-3 text-[var(--text-primary)] font-bold text-sm">
              <div className="h-10 w-auto rounded-lg bg-white px-2 py-0.5 border border-[var(--border-hairline)] shadow-2xs flex items-center justify-center">
                <img src={logoImg} alt="PRAMAANX" className="h-8 w-auto object-contain" />
              </div>
              <div>
                <span className="font-display tracking-tight text-base">{APP_NAME} DIGITAL FORENSICS</span>
                <span className="block font-mono text-[10px] text-[var(--text-muted)] font-normal">
                  AI-Assisted Investigation Platform • v{APP_VERSION}
                </span>
              </div>
            </div>
            <p className="text-xs text-[var(--text-muted)] leading-relaxed max-w-sm">
              Precision digital forensics and evidence inspection platform.
              Self-owned local neural inference, structural document dissection, and tamper detection with zero external cloud dependencies.
            </p>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-[var(--bg-subtle)] border border-[var(--border-hairline)] text-[11px] font-mono text-[var(--text-secondary)]">
              <Lock className="w-3 h-3 text-[var(--status-low)]" />
              <span>100% Air-Gapped / On-Premise Execution</span>
            </div>
          </div>

          {/* Column 2: Navigation Links */}
          <div className="md:col-span-4 space-y-2">
            <span className="text-[10px] font-mono uppercase font-bold text-[var(--text-primary)] tracking-widest block mb-3">
              Platform Modules
            </span>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              <Link to={ROUTES.HOME} className="hover:text-[var(--text-primary)] transition-colors">
                Home
              </Link>
              <Link to={ROUTES.ANALYZE} className="hover:text-[var(--text-primary)] transition-colors">
                Analyze Evidence
              </Link>
              <Link to={ROUTES.INVESTIGATIONS} className="hover:text-[var(--text-primary)] transition-colors">
                Investigations
              </Link>
              <Link to={ROUTES.VAULT} className="hover:text-[var(--text-primary)] transition-colors">
                Evidence Vault
              </Link>
              <Link to={ROUTES.REPORTS} className="hover:text-[var(--text-primary)] transition-colors">
                Forensic Reports
              </Link>
              <Link to={ROUTES.LEARN} className="hover:text-[var(--text-primary)] transition-colors">
                Learn Hub
              </Link>
              <Link to={ROUTES.DASHBOARD} className="hover:text-[var(--text-primary)] transition-colors">
                Dashboard
              </Link>
              <Link to={ROUTES.SETTINGS} className="hover:text-[var(--text-primary)] transition-colors">
                Settings
              </Link>
              <Link to={ROUTES.ABOUT} className="hover:text-[var(--text-primary)] transition-colors">
                About
              </Link>
            </div>
          </div>

          {/* Column 3: Forensic Protocol Disclosures */}
          <div className="md:col-span-3 space-y-2 text-[11px] font-mono">
            <span className="text-[10px] uppercase font-bold text-[var(--text-primary)] tracking-widest block mb-3">
              Evidentiary Standards
            </span>
            <p className="text-[var(--text-muted)] leading-relaxed">
              Adheres to ISO/IEC 27037 standards for digital evidence acquisition, integrity preservation, and chain of custody documentation.
            </p>
          </div>
        </div>

        <div className="mt-10 pt-6 border-t border-[var(--border-hairline)] flex flex-col sm:flex-row items-center justify-between gap-4 text-[11px] font-mono text-[var(--text-muted)]">
          <p>© 2026 PRAMAANX. Built for digital forensics education and research.</p>
          <p>Zero telemetry • Strict privacy • Open source primitives</p>
        </div>
      </div>
    </footer>
  );
}
