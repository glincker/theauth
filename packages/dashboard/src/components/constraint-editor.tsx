import { X } from "lucide-react";
import { useState } from "react";
import { Input, Label } from "./input.js";

// Constraint shape

interface RateLimit {
	maxCallsPerHour: number;
}

interface TimeWindow {
	start: string;
	end: string;
}

interface ParsedConstraints {
	rateLimit: RateLimit | null;
	timeWindow: TimeWindow | null;
	requireApproval: boolean;
	ipAllowlist: string[] | null;
	argumentPatterns: string[] | null;
}

function parseConstraints(raw: Record<string, unknown>): ParsedConstraints {
	const rateLimit =
		raw.rateLimit !== undefined && raw.rateLimit !== null ? (raw.rateLimit as RateLimit) : null;

	const timeWindow =
		raw.timeWindow !== undefined && raw.timeWindow !== null ? (raw.timeWindow as TimeWindow) : null;

	const requireApproval = raw.requireApproval === true;

	const ipAllowlist =
		Array.isArray(raw.ipAllowlist) && raw.ipAllowlist.length > 0
			? (raw.ipAllowlist as string[])
			: null;

	const argumentPatterns =
		Array.isArray(raw.argumentPatterns) && raw.argumentPatterns.length > 0
			? (raw.argumentPatterns as string[])
			: null;

	return { rateLimit, timeWindow, requireApproval, ipAllowlist, argumentPatterns };
}

function serializeConstraints(parsed: ParsedConstraints): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	if (parsed.rateLimit !== null) out.rateLimit = parsed.rateLimit;
	if (parsed.timeWindow !== null) out.timeWindow = parsed.timeWindow;
	if (parsed.requireApproval) out.requireApproval = true;
	if (parsed.ipAllowlist !== null) out.ipAllowlist = parsed.ipAllowlist;
	if (parsed.argumentPatterns !== null) out.argumentPatterns = parsed.argumentPatterns;
	return out;
}

// Sub-components

interface SectionToggleProps {
	id: string;
	label: string;
	enabled: boolean;
	onToggle: () => void;
	children: React.ReactNode;
}

function SectionToggle({ id, label, enabled, onToggle, children }: SectionToggleProps) {
	return (
		<div className="rounded-lg border border-zinc-200 dark:border-zinc-800 overflow-hidden">
			<button
				type="button"
				id={id}
				onClick={onToggle}
				className="w-full flex items-center justify-between px-3 py-2.5 bg-zinc-100/60 dark:bg-zinc-800/40 hover:bg-zinc-200/70 dark:bg-zinc-800/70 transition-colors"
				aria-expanded={enabled}
			>
				<span className="text-xs font-medium text-zinc-300">{label}</span>
				<span
					className={[
						"w-8 h-4 rounded-full transition-colors relative flex-shrink-0",
						enabled ? "bg-amber-600" : "bg-zinc-700",
					].join(" ")}
					aria-hidden="true"
				>
					<span
						className={[
							"absolute top-0.5 w-3 h-3 rounded-full bg-white transition-transform",
							enabled ? "translate-x-4" : "translate-x-0.5",
						].join(" ")}
					/>
				</span>
			</button>
			{enabled && <div className="px-3 py-3 space-y-2.5 border-t border-zinc-800">{children}</div>}
		</div>
	);
}

interface TagListProps {
	tags: string[];
	onRemove: (tag: string) => void;
}

function TagList({ tags, onRemove }: TagListProps) {
	if (tags.length === 0) return null;
	return (
		<div className="flex flex-wrap gap-1.5 mt-1.5">
			{tags.map((tag) => (
				<span
					key={tag}
					className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-zinc-100 dark:bg-zinc-800 border border-zinc-300 dark:border-zinc-700 text-xs text-zinc-700 dark:text-zinc-300 font-mono"
				>
					{tag}
					<button
						type="button"
						onClick={() => onRemove(tag)}
						className="text-zinc-500 hover:text-zinc-200 transition-colors"
						aria-label={`Remove ${tag}`}
					>
						<X className="w-2.5 h-2.5" />
					</button>
				</span>
			))}
		</div>
	);
}

// Main ConstraintEditor

export interface ConstraintEditorProps {
	constraints: Record<string, unknown>;
	onChange: (constraints: Record<string, unknown>) => void;
}

export function ConstraintEditor({ constraints, onChange }: ConstraintEditorProps) {
	const parsed = parseConstraints(constraints);

	// Pending text inputs (not yet committed to tags)
	const [ipInput, setIpInput] = useState("");
	const [patternInput, setPatternInput] = useState("");

	function update(partial: Partial<ParsedConstraints>) {
		onChange(serializeConstraints({ ...parsed, ...partial }));
	}

	// Rate limit
	function toggleRateLimit() {
		update({ rateLimit: parsed.rateLimit === null ? { maxCallsPerHour: 100 } : null });
	}

	// Time window
	function toggleTimeWindow() {
		update({ timeWindow: parsed.timeWindow === null ? { start: "09:00", end: "17:00" } : null });
	}

	// IP allowlist helpers
	function commitIpInput() {
		const entries = ipInput
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean);
		if (entries.length === 0) return;
		const current = parsed.ipAllowlist ?? [];
		const next = [...current, ...entries.filter((e) => !current.includes(e))];
		update({ ipAllowlist: next.length > 0 ? next : null });
		setIpInput("");
	}

	function removeIp(ip: string) {
		const next = (parsed.ipAllowlist ?? []).filter((x) => x !== ip);
		update({ ipAllowlist: next.length > 0 ? next : null });
	}

	// Argument pattern helpers
	function commitPatternInput() {
		const entries = patternInput
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean);
		if (entries.length === 0) return;
		const current = parsed.argumentPatterns ?? [];
		const next = [...current, ...entries.filter((e) => !current.includes(e))];
		update({ argumentPatterns: next.length > 0 ? next : null });
		setPatternInput("");
	}

	function removePattern(pattern: string) {
		const next = (parsed.argumentPatterns ?? []).filter((x) => x !== pattern);
		update({ argumentPatterns: next.length > 0 ? next : null });
	}

	return (
		<div className="space-y-2">
			{/* Rate limit */}
			<SectionToggle
				id="constraint-rate-limit"
				label="Rate limit"
				enabled={parsed.rateLimit !== null}
				onToggle={toggleRateLimit}
			>
				<div>
					<Label htmlFor="constraint-max-calls">Max calls per hour</Label>
					<Input
						id="constraint-max-calls"
						type="number"
						min={1}
						value={parsed.rateLimit?.maxCallsPerHour ?? 100}
						onChange={(e) => update({ rateLimit: { maxCallsPerHour: Number(e.target.value) } })}
						className="w-32"
					/>
				</div>
			</SectionToggle>

			{/* Time window */}
			<SectionToggle
				id="constraint-time-window"
				label="Time window"
				enabled={parsed.timeWindow !== null}
				onToggle={toggleTimeWindow}
			>
				<div className="flex items-center gap-3">
					<div>
						<Label htmlFor="constraint-tw-start">Start</Label>
						<Input
							id="constraint-tw-start"
							type="time"
							value={parsed.timeWindow?.start ?? "09:00"}
							onChange={(e) =>
								update({
									timeWindow: {
										start: e.target.value,
										end: parsed.timeWindow?.end ?? "17:00",
									},
								})
							}
							className="w-32"
						/>
					</div>
					<div>
						<Label htmlFor="constraint-tw-end">End</Label>
						<Input
							id="constraint-tw-end"
							type="time"
							value={parsed.timeWindow?.end ?? "17:00"}
							onChange={(e) =>
								update({
									timeWindow: {
										start: parsed.timeWindow?.start ?? "09:00",
										end: e.target.value,
									},
								})
							}
							className="w-32"
						/>
					</div>
				</div>
			</SectionToggle>

			{/* Human-in-the-loop */}
			<label className="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-100/60 dark:bg-zinc-800/40 cursor-pointer hover:bg-zinc-200/70 dark:bg-zinc-800/70 transition-colors">
				<input
					type="checkbox"
					checked={parsed.requireApproval}
					onChange={() => update({ requireApproval: !parsed.requireApproval })}
					className="w-3.5 h-3.5 rounded border-zinc-600 bg-zinc-100 dark:bg-zinc-800 accent-amber-500"
				/>
				<span className="text-xs font-medium text-zinc-300">
					Human-in-the-loop (require approval)
				</span>
			</label>

			{/* IP allowlist */}
			<SectionToggle
				id="constraint-ip-allowlist"
				label="IP allowlist"
				enabled={parsed.ipAllowlist !== null}
				onToggle={() => update({ ipAllowlist: parsed.ipAllowlist === null ? [] : null })}
			>
				<div>
					<Label htmlFor="constraint-ip-input">
						Add IPs or CIDRs (comma-separated, press Enter)
					</Label>
					<Input
						id="constraint-ip-input"
						placeholder="10.0.0.0/8, 192.168.1.5"
						value={ipInput}
						onChange={(e) => setIpInput(e.target.value)}
						onKeyDown={(e) => {
							if (e.key === "Enter") {
								e.preventDefault();
								commitIpInput();
							}
						}}
						onBlur={commitIpInput}
					/>
					<TagList tags={parsed.ipAllowlist ?? []} onRemove={removeIp} />
				</div>
			</SectionToggle>

			{/* Argument patterns */}
			<SectionToggle
				id="constraint-arg-patterns"
				label="Argument patterns"
				enabled={parsed.argumentPatterns !== null}
				onToggle={() => update({ argumentPatterns: parsed.argumentPatterns === null ? [] : null })}
			>
				<div>
					<Label htmlFor="constraint-pattern-input">
						Glob patterns (comma-separated, press Enter)
					</Label>
					<Input
						id="constraint-pattern-input"
						placeholder="docs/*, reports/**"
						value={patternInput}
						onChange={(e) => setPatternInput(e.target.value)}
						onKeyDown={(e) => {
							if (e.key === "Enter") {
								e.preventDefault();
								commitPatternInput();
							}
						}}
						onBlur={commitPatternInput}
					/>
					<TagList tags={parsed.argumentPatterns ?? []} onRemove={removePattern} />
				</div>
			</SectionToggle>
		</div>
	);
}
