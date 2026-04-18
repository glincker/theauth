"use client";

import { useState } from "react";

interface CollapsibleProps {
	label: string;
	children: React.ReactNode;
}

export function Collapsible({ label, children }: CollapsibleProps) {
	const [open, setOpen] = useState(false);

	return (
		<div className="mt-4 border border-zinc-800 rounded-lg overflow-hidden">
			<button
				type="button"
				onClick={() => setOpen((v) => !v)}
				className="w-full flex items-center justify-between px-4 py-2 text-sm text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50 transition-colors"
			>
				<span>{label}</span>
				<span className="text-xs">{open ? "▲" : "▼"}</span>
			</button>
			{open && <div className="border-t border-zinc-800">{children}</div>}
		</div>
	);
}
