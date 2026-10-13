import type { ReactNode } from "react";

type BadgeVariant = "green" | "red" | "yellow" | "gray" | "blue" | "indigo" | "gold";

interface BadgeProps {
	variant: BadgeVariant;
	children: ReactNode;
}

const VARIANT_CLASSES: Record<BadgeVariant, string> = {
	green: "bg-emerald-950 text-emerald-400 border-emerald-800",
	red: "bg-red-950 text-red-400 border-red-800",
	yellow: "bg-amber-950 text-amber-400 border-amber-800",
	gray: "bg-zinc-100 dark:bg-zinc-800 text-zinc-400 border-zinc-700",
	blue: "bg-blue-950 text-blue-400 border-blue-800",
	indigo: "bg-indigo-950 text-indigo-400 border-indigo-800",
	gold: "bg-amber-950 text-amber-400 border-amber-700",
};

export function Badge({ variant, children }: BadgeProps) {
	return (
		<span
			className={[
				"inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border",
				VARIANT_CLASSES[variant],
			].join(" ")}
		>
			{children}
		</span>
	);
}

// Dot indicator

interface StatusDotProps {
	variant: BadgeVariant;
}

const DOT_CLASSES: Record<BadgeVariant, string> = {
	green: "bg-emerald-400",
	red: "bg-red-400",
	yellow: "bg-amber-400",
	gray: "bg-zinc-500",
	blue: "bg-blue-400",
	indigo: "bg-indigo-400",
	gold: "bg-amber-400",
};

export function StatusDot({ variant }: StatusDotProps) {
	return (
		<span className={["w-1.5 h-1.5 rounded-full flex-shrink-0", DOT_CLASSES[variant]].join(" ")} />
	);
}
