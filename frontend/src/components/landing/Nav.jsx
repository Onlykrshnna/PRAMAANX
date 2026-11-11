import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Menu, X, ArrowUpRight, Sun, Moon } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { ROUTES } from '../../utils/constants';

const NAV_LINKS = [
  { id: 'top', label: 'Home', href: '#top' },
  { id: 'features', label: 'Features', href: '#features' },
  { id: 'why', label: 'Why PRAMAANX', href: '#why' },
  { id: 'how', label: 'How it works', href: '#how' },
  { id: 'limits', label: 'Limits', href: '#limits' },
];

export default function Nav() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [activeId, setActiveId] = useState('top');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [isRotating, setIsRotating] = useState(false);
  const [indicator, setIndicator] = useState({ left: 5, width: 0, opacity: 0 });

  const { effectiveTheme, setTheme } = useTheme();
  const isDark = effectiveTheme === 'dark';
  const navigate = useNavigate();

  const headerRef = useRef(null);
  const linkRefs = useRef({});
  const mobileSheetRef = useRef(null);

  // 1. Scroll listener for >8px border/blur transition & scroll-spy
  useEffect(() => {
    const handleScroll = () => {
      const scrollY = window.scrollY;
      setIsScrolled(scrollY > 8);

      // Section scroll-spy with offset for sticky nav (72px + buffer)
      const scrollPos = scrollY + 110;
      let currentId = 'top';

      for (let i = NAV_LINKS.length - 1; i >= 0; i--) {
        const link = NAV_LINKS[i];
        const section = document.getElementById(link.id);
        if (section) {
          const top = section.offsetTop;
          if (scrollPos >= top) {
            currentId = link.id;
            break;
          }
        }
      }
      setActiveId(currentId);
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // 2. Sliding highlight pill indicator calculation
  const updateIndicator = useCallback(() => {
    const activeEl = linkRefs.current[activeId];
    if (activeEl) {
      setIndicator({
        left: activeEl.offsetLeft,
        width: activeEl.offsetWidth,
        opacity: 1,
      });
    }
  }, [activeId]);

  useEffect(() => {
    updateIndicator();
    window.addEventListener('resize', updateIndicator);
    return () => window.removeEventListener('resize', updateIndicator);
  }, [updateIndicator]);

  // 3. Smooth scrolling on link click with scroll-padding-top: 88px
  const handleLinkClick = (e, href, id) => {
    e.preventDefault();
    setActiveId(id);
    setMobileMenuOpen(false);

    if (href === '#top') {
      window.scrollTo({ top: 0, behavior: 'smooth' });
      window.history.pushState(null, '', ' ');
      return;
    }

    const target = document.querySelector(href);
    if (target) {
      target.scrollIntoView({ behavior: 'smooth' });
      window.history.pushState(null, '', href);
    }
  };

  // 4. Rotate 200ms on theme toggle
  const toggleTheme = () => {
    setIsRotating(true);
    setTheme(isDark ? 'light' : 'dark');
    setTimeout(() => setIsRotating(false), 200);
  };

  // 5. Close mobile sheet on Escape key
  useEffect(() => {
    if (!mobileMenuOpen) return;

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setMobileMenuOpen(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [mobileMenuOpen]);

  // 6. Close mobile sheet on outside click
  useEffect(() => {
    if (!mobileMenuOpen) return;

    const handleClickOutside = (e) => {
      if (headerRef.current && !headerRef.current.contains(e.target)) {
        setMobileMenuOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('touchstart', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('touchstart', handleClickOutside);
    };
  }, [mobileMenuOpen]);

  // 7. Focus trap while mobile sheet is open
  useEffect(() => {
    if (!mobileMenuOpen || !mobileSheetRef.current) return;

    const focusableEls = mobileSheetRef.current.querySelectorAll(
      'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );
    if (focusableEls.length > 0) {
      focusableEls[0].focus();
    }

    const handleTabKey = (e) => {
      if (e.key !== 'Tab') return;
      const firstEl = focusableEls[0];
      const lastEl = focusableEls[focusableEls.length - 1];

      if (e.shiftKey) {
        if (document.activeElement === firstEl) {
          lastEl.focus();
          e.preventDefault();
        }
      } else {
        if (document.activeElement === lastEl) {
          firstEl.focus();
          e.preventDefault();
        }
      }
    };

    window.addEventListener('keydown', handleTabKey);
    return () => window.removeEventListener('keydown', handleTabKey);
  }, [mobileMenuOpen]);

  return (
    <header
      ref={headerRef}
      className={`sticky top-0 z-50 w-full transition-all duration-200 ${
        isScrolled
          ? 'border-b border-[var(--line)] bg-[var(--bg)]/80 backdrop-blur-[14px]'
          : 'border-b border-transparent bg-transparent'
      }`}
    >
      <div className="max-w-[1160px] mx-auto px-6 h-[72px] flex items-center justify-between">
        {/* Left: Creative Typographic Wordmark */}
        <a
          href="#top"
          onClick={(e) => handleLinkClick(e, '#top', 'top')}
          className="flex items-center select-none hover:opacity-90 transition-opacity focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand)] rounded-lg py-1"
          aria-label="PRAMAANX Home"
        >
          <span
            className="font-extrabold text-[21px] sm:text-[22px] tracking-tight text-[var(--ink)] font-sans"
            style={{ fontFamily: 'Manrope, sans-serif' }}
          >
            PRAMAAN<span className="text-[var(--brand)] font-black">X</span>
          </span>
        </a>

        {/* Center: Pill container (border 1px --line, bg --card, radius 999px, padding 5px) */}
        <nav
          role="navigation"
          aria-label="Main Navigation"
          className="hidden min-[860px]:flex items-center relative rounded-full border border-[var(--line)] bg-[var(--card)] p-[5px] shadow-xs"
        >
          {/* Sliding highlight pill (animates position and width over 300ms) */}
          <div
            className="absolute rounded-full bg-[var(--soft)] pointer-events-none transition-all duration-300 ease-out"
            style={{
              left: `${indicator.left}px`,
              width: `${indicator.width}px`,
              top: '5px',
              bottom: '5px',
              opacity: indicator.opacity,
            }}
          />

          {NAV_LINKS.map((link) => {
            const isActive = activeId === link.id;
            return (
              <a
                key={link.id}
                ref={(el) => (linkRefs.current[link.id] = el)}
                href={link.href}
                onClick={(e) => handleLinkClick(e, link.href, link.id)}
                aria-current={isActive ? 'page' : undefined}
                className={`relative z-10 px-4 py-[9px] rounded-full text-[14px] font-bold select-none cursor-pointer transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand)] ${
                  isActive ? 'text-[var(--ink)]' : 'text-[var(--mute)] hover:text-[var(--ink)]'
                }`}
                style={{ fontFamily: 'Manrope, sans-serif' }}
              >
                {link.label}
              </a>
            );
          })}
        </nav>

        {/* Right: 40px round theme toggle + dark primary button "Analyze evidence" */}
        <div className="hidden min-[860px]:flex items-center gap-3">
          {/* 40px round theme toggle (Lucide Sun/Moon with 200ms rotate) */}
          <button
            type="button"
            onClick={toggleTheme}
            className="w-10 h-10 rounded-full border border-[var(--line)] bg-[var(--card)] flex items-center justify-center text-[var(--mute)] hover:text-[var(--ink)] hover:border-[var(--brand)] shadow-xs transition-transform duration-200 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand)] select-none shrink-0"
            style={{
              transform: isRotating ? 'rotate(90deg)' : 'rotate(0deg)',
            }}
            title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {isDark ? (
              <Sun className="w-[18px] h-[18px] text-[var(--warn)]" />
            ) : (
              <Moon className="w-[18px] h-[18px] text-[var(--brand)]" />
            )}
          </button>

          {/* Dark primary button "Analyze evidence" in Manrope 700 15px, Sentence Case */}
          <button
            type="button"
            onClick={() => navigate(ROUTES.ANALYZE)}
            className="inline-flex items-center gap-1.5 px-5 py-2.5 rounded-full font-bold text-[15px] bg-[var(--ink)] text-[var(--bg)] shadow-xs cursor-pointer select-none transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand)] shrink-0"
            style={{ fontFamily: 'Manrope, sans-serif' }}
          >
            <span>Analyze evidence</span>
            <ArrowUpRight className="w-4 h-4" />
          </button>
        </div>

        {/* Below 860px: Hamburger Button (Lucide Menu/X) */}
        <div className="flex min-[860px]:hidden items-center gap-2">
          <button
            type="button"
            onClick={() => setMobileMenuOpen((prev) => !prev)}
            className="w-10 h-10 rounded-full border border-[var(--line)] bg-[var(--card)] flex items-center justify-center text-[var(--ink)] hover:bg-[var(--soft)] transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand)]"
            aria-label={mobileMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            aria-expanded={mobileMenuOpen}
            aria-controls="mobile-nav-sheet"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Full-width Sheet under the Nav (Below 860px) */}
      {mobileMenuOpen && (
        <div
          id="mobile-nav-sheet"
          ref={mobileSheetRef}
          className="min-[860px]:hidden absolute top-[72px] left-0 right-0 w-full bg-[var(--card)] border-b border-[var(--line)] shadow-xl z-50 p-6 space-y-4 animate-in fade-in slide-in-from-top-2 duration-200"
        >
          <nav className="flex flex-col space-y-1">
            {NAV_LINKS.map((link) => {
              const isActive = activeId === link.id;
              return (
                <a
                  key={link.id}
                  href={link.href}
                  onClick={(e) => handleLinkClick(e, link.href, link.id)}
                  aria-current={isActive ? 'page' : undefined}
                  className={`min-h-[48px] flex items-center px-4 rounded-xl text-[15px] font-bold transition-colors select-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand)] ${
                    isActive
                      ? 'bg-[var(--soft)] text-[var(--ink)]'
                      : 'text-[var(--mute)] hover:text-[var(--ink)] hover:bg-[var(--soft)]/50'
                  }`}
                  style={{ fontFamily: 'Manrope, sans-serif' }}
                >
                  {link.label}
                </a>
              );
            })}
          </nav>

          {/* Mobile Sheet Footer: Theme Toggle & CTA */}
          <div className="pt-4 border-t border-[var(--line)] flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs font-bold text-[var(--mute)]">
              <span>Theme:</span>
              <button
                type="button"
                onClick={toggleTheme}
                className="w-10 h-10 rounded-full border border-[var(--line)] bg-[var(--soft)] flex items-center justify-center text-[var(--mute)] hover:text-[var(--ink)] shadow-xs transition-transform duration-200 cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand)]"
                style={{
                  transform: isRotating ? 'rotate(90deg)' : 'rotate(0deg)',
                }}
                aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
              >
                {isDark ? (
                  <Sun className="w-4 h-4 text-[var(--warn)]" />
                ) : (
                  <Moon className="w-4 h-4 text-[var(--brand)]" />
                )}
              </button>
            </div>

            <button
              type="button"
              onClick={() => {
                setMobileMenuOpen(false);
                navigate(ROUTES.ANALYZE);
              }}
              className="flex-1 min-h-[48px] inline-flex items-center justify-center gap-1.5 px-5 py-2.5 rounded-full font-bold text-[15px] bg-[var(--ink)] text-[var(--bg)] shadow-xs cursor-pointer select-none transition-all duration-200 hover:-translate-y-0.5 hover:shadow-md focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--brand)]"
              style={{ fontFamily: 'Manrope, sans-serif' }}
            >
              <span>Analyze evidence</span>
              <ArrowUpRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </header>
  );
}
