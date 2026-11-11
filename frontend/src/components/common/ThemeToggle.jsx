import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';

export default function ThemeToggle({ className = '', compact = false }) {
  const { effectiveTheme, setTheme } = useTheme();
  const isDark = effectiveTheme === 'dark';

  const toggleTheme = () => {
    setTheme(isDark ? 'light' : 'dark');
  };

  const paddingClass = compact ? 'p-2' : 'p-2.5';

  return (
    <button
      type="button"
      onClick={toggleTheme}
      className={`inline-flex items-center justify-center ${paddingClass} rounded-full border border-[var(--line)] bg-[var(--card)] text-[var(--mute)] hover:text-[var(--ink)] hover:border-[var(--brand)] shadow-xs transition-all cursor-pointer lift-button ${className}`}
      title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
    >
      {isDark ? (
        <Sun className="w-4 h-4 text-[var(--warn)]" />
      ) : (
        <Moon className="w-4 h-4 text-[var(--brand)]" />
      )}
    </button>
  );
}
