export default function ViewTabs({
  tabs = [
    { id: 'original', label: 'Original' },
    { id: 'heatmap', label: 'AI heatmap' },
    { id: 'compression', label: 'Compression' },
  ],
  activeTab = 'original',
  onChange,
  className = '',
}) {
  return (
    <div
      role="tablist"
      aria-label="Inspection views"
      className={`inline-flex items-center p-1 rounded-full border border-[var(--line)] bg-[var(--card)]/90 backdrop-blur-xs shadow-xs ${className}`}
    >
      {tabs.map((tab) => {
        const isActive = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            role="tab"
            type="button"
            aria-selected={isActive}
            onClick={() => onChange && onChange(tab.id)}
            className={`px-3.5 py-1.5 rounded-full text-xs font-mono font-medium transition-all cursor-pointer ${
              isActive
                ? 'bg-[var(--brand)] text-white shadow-xs font-bold'
                : 'text-[var(--mute)] hover:text-[var(--ink)] hover:bg-[var(--soft)]'
            }`}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
}

