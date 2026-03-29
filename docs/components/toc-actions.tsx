"use client";

import { Copy, Sparkles, ChevronDown, Check, ExternalLink } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import posthog from "posthog-js";

interface TocActionsProps {
	slug: string;
}

const RAW_BASE =
	"https://raw.githubusercontent.com/kavachos/kavachos/main/docs/content/docs";

const AI_SYSTEM_PREFIX =
	"You are a helpful assistant. The following is documentation from the KavachOS project. Please help me understand it.\n\n---\n\n";

async function fetchMarkdown(slug: string): Promise<string> {
	const url = `${RAW_BASE}/${slug}.mdx`;
	const res = await fetch(url);
	if (!res.ok) throw new Error(`Failed to fetch: ${res.status}`);
	return res.text();
}

export function TocActions({ slug }: TocActionsProps) {
	const [copied, setCopied] = useState(false);
	const [aiOpen, setAiOpen] = useState(false);
	const [loading, setLoading] = useState<"copy" | "ai-copy" | null>(null);
	const dropdownRef = useRef<HTMLDivElement>(null);

	// Close dropdown on outside click
	useEffect(() => {
		if (!aiOpen) return;
		function handleClick(e: MouseEvent) {
			if (
				dropdownRef.current &&
				!dropdownRef.current.contains(e.target as Node)
			) {
				setAiOpen(false);
			}
		}
		document.addEventListener("mousedown", handleClick);
		return () => document.removeEventListener("mousedown", handleClick);
	}, [aiOpen]);

	async function handleCopyMarkdown() {
		setLoading("copy");
		try {
			const text = await fetchMarkdown(slug);
			await navigator.clipboard.writeText(text);
			posthog.capture("doc_page_markdown_copied", { slug });
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		} catch {
			// Fallback: copy the URL itself
			const url = `${RAW_BASE}/${slug}.mdx`;
			await navigator.clipboard.writeText(url).catch(() => null);
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		} finally {
			setLoading(null);
		}
	}

	function handleOpenChatGPT() {
		const url = `${RAW_BASE}/${slug}.mdx`;
		const target = `https://chat.openai.com/?q=${encodeURIComponent(
			`Read this documentation and help me: ${url}`,
		)}`;
		window.open(target, "_blank", "noopener,noreferrer");
		posthog.capture("doc_page_opened_in_chatgpt", { slug });
		setAiOpen(false);
	}

	function handleOpenClaude() {
		window.open("https://claude.ai/new", "_blank", "noopener,noreferrer");
		posthog.capture("doc_page_opened_in_claude", { slug });
		setAiOpen(false);
	}

	async function handleCopyForAI() {
		setLoading("ai-copy");
		setAiOpen(false);
		try {
			const text = await fetchMarkdown(slug);
			await navigator.clipboard.writeText(AI_SYSTEM_PREFIX + text);
			posthog.capture("doc_page_copied_for_ai", { slug });
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		} catch {
			const url = `${RAW_BASE}/${slug}.mdx`;
			await navigator.clipboard
				.writeText(AI_SYSTEM_PREFIX + url)
				.catch(() => null);
			setCopied(true);
			setTimeout(() => setCopied(false), 2000);
		} finally {
			setLoading(null);
		}
	}

	const isBusy = loading !== null;

	return (
		<div className="flex items-center gap-1 shrink-0 mt-2">
			{/* Copy as Markdown */}
			<button
				type="button"
				onClick={handleCopyMarkdown}
				disabled={isBusy}
				title="Copy page as Markdown"
				className="group flex items-center gap-1.5 rounded-md px-2 py-1.5 text-xs text-fd-muted-foreground transition-colors hover:text-fd-foreground hover:bg-fd-accent disabled:opacity-50 disabled:cursor-not-allowed"
			>
				{copied && loading === null ? (
					<Check className="h-3 w-3 text-[var(--kavach-gold-primary)]" />
				) : (
					<Copy className="h-3 w-3" />
				)}
				<span>{copied && loading === null ? "Copied!" : "Copy MD"}</span>
			</button>

			{/* Open in AI dropdown */}
			<div ref={dropdownRef} className="relative">
				<button
					type="button"
					onClick={() => setAiOpen((v) => !v)}
					disabled={isBusy}
					title="Open in AI assistant"
					className="group flex items-center gap-1.5 rounded-md px-2 py-1.5 text-xs text-fd-muted-foreground transition-colors hover:text-fd-foreground hover:bg-fd-accent disabled:opacity-50 disabled:cursor-not-allowed"
					aria-expanded={aiOpen}
					aria-haspopup="menu"
				>
					<Sparkles className="h-3 w-3" />
					<span>Open in AI</span>
					<ChevronDown
						className={`h-2.5 w-2.5 transition-transform duration-150 ${aiOpen ? "rotate-180" : ""}`}
					/>
				</button>

				{aiOpen && (
					<div
						role="menu"
						className="absolute left-0 top-full z-50 mt-1 w-44 overflow-hidden rounded-lg border border-fd-border bg-fd-popover py-1 shadow-lg"
					>
						<button
							type="button"
							role="menuitem"
							onClick={handleOpenChatGPT}
							className="flex w-full items-center gap-2 px-3 py-2 text-xs text-fd-muted-foreground transition-colors hover:bg-fd-accent hover:text-fd-foreground"
						>
							<ExternalLink className="h-3 w-3 shrink-0" />
							Open in ChatGPT
						</button>
						<button
							type="button"
							role="menuitem"
							onClick={handleOpenClaude}
							className="flex w-full items-center gap-2 px-3 py-2 text-xs text-fd-muted-foreground transition-colors hover:bg-fd-accent hover:text-fd-foreground"
						>
							<ExternalLink className="h-3 w-3 shrink-0" />
							Open in Claude
						</button>
						<div className="my-1 h-px bg-fd-border" role="separator" />
						<button
							type="button"
							role="menuitem"
							onClick={handleCopyForAI}
							className="flex w-full items-center gap-2 px-3 py-2 text-xs text-fd-muted-foreground transition-colors hover:bg-fd-accent hover:text-fd-foreground"
						>
							<Copy className="h-3 w-3 shrink-0" />
							Copy for AI
						</button>
					</div>
				)}
			</div>
		</div>
	);
}
