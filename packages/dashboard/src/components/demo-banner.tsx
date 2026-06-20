import { X } from "lucide-react";
import { useState } from "react";

const STORAGE_KEY = "theauth-demo-banner-dismissed";

function isDismissed(): boolean {
	if (typeof window === "undefined") return false;
	return sessionStorage.getItem(STORAGE_KEY) === "true";
}

export function DemoBanner() {
	const [dismissed, setDismissed] = useState<boolean>(isDismissed);

	if (dismissed) return null;

	function dismiss() {
		sessionStorage.setItem(STORAGE_KEY, "true");
		setDismissed(true);
	}

	return (
		<div className="flex items-center gap-3 px-4 py-2.5 bg-amber-950/60 border-b border-amber-700/40 text-amber-300">
			<div className="flex-1 flex items-center gap-2 text-xs font-medium">
				<span className="inline-block w-2 h-2 rounded-full bg-amber-400 flex-shrink-0" />
				Running in demo mode with sample data.{" "}
				<a
					href="https://theauth.com/docs"
					target="_blank"
					rel="noopener noreferrer"
					className="underline underline-offset-2 hover:text-amber-200 transition-colors"
				>
					Read the docs
				</a>{" "}
				to set up your own instance.
			</div>
			<button
				type="button"
				onClick={dismiss}
				className="flex-shrink-0 text-amber-500 hover:text-amber-300 transition-colors"
				aria-label="Dismiss demo banner"
			>
				<X className="w-3.5 h-3.5" />
			</button>
		</div>
	);
}
