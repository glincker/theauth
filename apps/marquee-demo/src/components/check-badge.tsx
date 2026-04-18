"use client";

interface CheckBadgeProps {
	done: boolean;
}

export function CheckBadge({ done }: CheckBadgeProps) {
	if (!done) return null;
	return (
		<span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 text-xs font-bold">
			✓
		</span>
	);
}
