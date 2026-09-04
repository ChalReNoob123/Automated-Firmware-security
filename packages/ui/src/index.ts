export function ConfidenceBadge({ level }: { level: 'Confirmed' | 'Likely' | 'Unconfirmed' }) {
  const color =
    level === 'Confirmed' ? 'bg-emerald-500/15 text-emerald-200 border-emerald-400/30'
    : level === 'Likely' ? 'bg-amber-500/15 text-amber-200 border-amber-400/30'
    : 'bg-slate-500/15 text-slate-300 border-slate-400/30';
  return `<span class="rounded-full border px-2.5 py-1 text-xs ${color}">${level}</span>`;
}
