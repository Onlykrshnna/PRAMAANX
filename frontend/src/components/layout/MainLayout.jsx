/**
 * PRAMAANX - Primary Architectural Laboratory Layout
 * Shell wrapping precision navigation, main research canvas, and laboratory footer.
 */

import { Outlet, useLocation } from 'react-router-dom';
import Navbar from './Navbar';
import Footer from './Footer';

export default function MainLayout() {
  const location = useLocation();
  const isLanding = location.pathname === '/' || location.pathname === '/landing';

  if (isLanding) {
    return (
      <div className="min-h-screen bg-[var(--bg-canvas)] text-[var(--text-primary)] transition-colors duration-200">
        <Outlet />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[var(--bg-canvas)] text-[var(--text-primary)] flex flex-col font-sans selection:bg-[var(--accent-subtle)] selection:text-[var(--accent-cobalt)] transition-colors duration-200">
      {/* Accessible skip link */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-50 px-4 py-2 rounded-md bg-[var(--accent-cobalt)] text-white text-xs font-mono font-medium shadow-lg"
      >
        Skip to main forensic canvas
      </a>

      {/* Top Laboratory Navigation Bar */}
      <Navbar />

      {/* Primary Page Canvas with subtle architectural boundary */}
      <main
        id="main-content"
        className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12"
      >
        <Outlet />
      </main>

      {/* Global Laboratory Footer */}
      <Footer />
    </div>
  );
}
