/**
 * PRAMAANX - Architectural Laboratory Navigation Bar
 * Features official PRAMAANX emblem logo, balanced navigation links,
 * live engine health status, theme toggle, and direct evidence intake CTA.
 */

import { useState, useEffect } from 'react';
import { NavLink, Link, useNavigate } from 'react-router-dom';
import { Menu, X, ArrowRight, LayoutDashboard, FileSearch } from 'lucide-react';
import Button from '../common/Button';
import ThemeToggle from '../common/ThemeToggle';
import { ROUTES } from '../../utils/constants';
import { checkBackendHealth } from '../../services/healthService';

const NAV_LINKS = [
  { name: 'Home', path: ROUTES.HOME },
  { name: 'Analyze', path: ROUTES.ANALYZE },
  { name: 'Investigations', path: ROUTES.INVESTIGATIONS },
  { name: 'Vault', path: ROUTES.VAULT },
  { name: 'Reports', path: ROUTES.REPORTS },
  { name: 'Learn', path: ROUTES.LEARN },
];

export default function Navbar() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [engineStatus, setEngineStatus] = useState({ isOnline: false, version: '1.0.0', loading: true });
  const [scrolled, setScrolled] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    let isMounted = true;

    async function pollHealth() {
      const res = await checkBackendHealth();
      if (isMounted) {
        setEngineStatus({
          isOnline: res.isOnline,
          version: res.data?.version || '1.0.0',
          loading: false,
        });
      }
    }

    pollHealth();
    const interval = setInterval(pollHealth, 15000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <header
      className={`sticky top-0 z-40 transition-all duration-200 border-b ${
        scrolled
          ? 'bg-[var(--bg-canvas)]/90 backdrop-blur-md border-[var(--border-strong)] shadow-xs'
          : 'bg-[var(--bg-canvas)] border-[var(--border-hairline)]'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 sm:h-20">
          {/* Brand Logo & Wordmark (Left) */}
          <Link to={ROUTES.HOME} className="flex items-center gap-2 select-none hover:opacity-90 transition-opacity shrink-0">
            <span className="font-extrabold text-[20px] tracking-tight text-[var(--ink)] font-sans">
              PRAMAAN<span className="text-[var(--brand)] font-black">X</span>
            </span>
            <span className="hidden sm:inline-block font-mono text-[9px] uppercase tracking-wider text-[var(--brand)] px-2 py-0.5 rounded-full border border-[var(--line)] bg-[var(--soft)] font-bold">
              LAB
            </span>
          </Link>

          {/* Center Navigation Links (Visible on desktop/laptop) */}
          <nav className="hidden lg:flex items-center gap-1 p-1 rounded-xl border border-[var(--border-hairline)] bg-[var(--bg-surface)]">
            {NAV_LINKS.map((link) => (
              <NavLink
                key={link.path}
                to={link.path}
                end={link.path === '/'}
                className={({ isActive }) =>
                  `px-3.5 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                    isActive
                      ? 'text-[var(--text-primary)] bg-[var(--bg-subtle)] font-bold shadow-2xs'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-subtle)]/60'
                  }`
                }
              >
                {link.name}
              </NavLink>
            ))}
          </nav>

          {/* Right Action Utilities (Horizontally Centered & Symmetrical) */}
          <div className="hidden sm:flex items-center gap-2.5 shrink-0">
            {/* Live Engine Status Chip */}
            <div
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono border border-[var(--border-hairline)] bg-[var(--bg-subtle)] text-[var(--text-muted)] select-none"
              title={
                engineStatus.isOnline
                  ? `PRAMAANX Core Engine v${engineStatus.version} Active & Ready`
                  : 'FastAPI Backend offline on local port 8000'
              }
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  engineStatus.isOnline
                    ? 'bg-[var(--status-low)]'
                    : 'bg-[var(--status-medium)]'
                }`}
              />
              <span className="text-[var(--text-secondary)] font-medium">
                {engineStatus.isOnline ? 'Active' : 'Standby'}
              </span>
            </div>

            {/* Persistent Theme Selector */}
            <ThemeToggle compact={false} />

            {/* Dashboard Shortcut */}
            <Button
              variant="outline"
              size="sm"
              icon={LayoutDashboard}
              onClick={() => navigate(ROUTES.DASHBOARD)}
              className="hidden xl:inline-flex"
            >
              Dashboard
            </Button>

            {/* Analyze Intake Action */}
            <Button
              variant="accent"
              size="sm"
              icon={FileSearch}
              onClick={() => navigate(ROUTES.ANALYZE)}
            >
              Analyze Evidence
            </Button>
          </div>

          {/* Mobile Actions: Theme toggle + Menu trigger */}
          <div className="flex sm:hidden items-center gap-2">
            <ThemeToggle compact={true} />
            <button
              type="button"
              onClick={() => setMobileMenuOpen((prev) => !prev)}
              className="p-2 rounded-lg text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-subtle)] border border-[var(--border-hairline)] cursor-pointer"
              aria-label="Toggle navigation menu"
            >
              {mobileMenuOpen ? (
                <X className="w-5 h-5" />
              ) : (
                <Menu className="w-5 h-5" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Drawer Menu */}
      {mobileMenuOpen && (
        <div className="lg:hidden border-b border-[var(--border-strong)] bg-[var(--bg-surface)] px-4 pt-3 pb-5 space-y-3">
          <div className="space-y-1">
            {NAV_LINKS.map((link) => (
              <NavLink
                key={link.path}
                to={link.path}
                end={link.path === '/'}
                onClick={() => setMobileMenuOpen(false)}
                className={({ isActive }) =>
                  `block px-3 py-2 rounded-lg text-sm font-mono font-medium ${
                    isActive
                      ? 'text-[var(--text-primary)] bg-[var(--bg-subtle)] font-bold'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-subtle)]'
                  }`
                }
              >
                {link.name}
              </NavLink>
            ))}
          </div>

          <div className="pt-3 border-t border-[var(--border-hairline)] flex flex-col gap-2.5">
            <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-[var(--bg-subtle)] border border-[var(--border-hairline)] text-xs font-mono">
              <span className="text-[var(--text-muted)]">Core Engine:</span>
              <div className="flex items-center gap-1.5 font-medium text-[var(--text-primary)]">
                <span
                  className={`w-2 h-2 rounded-full ${
                    engineStatus.isOnline ? 'bg-[var(--status-low)]' : 'bg-[var(--status-medium)]'
                  }`}
                />
                {engineStatus.isOnline ? 'Engine Active' : 'Engine Standby'}
              </div>
            </div>

            <Button
              variant="outline"
              size="sm"
              icon={LayoutDashboard}
              className="w-full justify-center"
              onClick={() => {
                setMobileMenuOpen(false);
                navigate(ROUTES.DASHBOARD);
              }}
            >
              Dashboard
            </Button>
            <Button
              variant="accent"
              size="sm"
              icon={ArrowRight}
              iconPosition="right"
              className="w-full justify-center"
              onClick={() => {
                setMobileMenuOpen(false);
                navigate(ROUTES.ANALYZE);
              }}
            >
              Analyze Evidence
            </Button>
          </div>
        </div>
      )}
    </header>
  );
}
