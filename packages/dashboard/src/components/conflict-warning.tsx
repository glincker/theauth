import { AlertTriangle } from "lucide-react";
import type { PermissionTemplate } from "../api/types.js";

// Conflict detection logic

interface ConflictResult {
	kind: "overlap" | "redundancy" | "contradiction";
	message: string;
	otherName: string;
}

/**
 * Returns true when two resource patterns can match the same resource.
 * Treats '*' anywhere as a wildcard segment and handles prefix matching.
 */
function patternsOverlap(a: string, b: string): boolean {
	// Identical patterns always overlap
	if (a === b) return true;

	// One is a pure wildcard
	if (a === "*" || b === "*") return true;

	// Prefix/suffix wildcard: "mcp:github:*" overlaps with "mcp:*"
	function matches(pattern: string, subject: string): boolean {
		if (pattern === subject) return true;
		if (pattern.endsWith(":*") || pattern.endsWith("/*") || pattern.endsWith("*")) {
			const prefix = pattern.endsWith(":*")
				? pattern.slice(0, -2)
				: pattern.endsWith("/*")
					? pattern.slice(0, -2)
					: pattern.slice(0, -1);
			return subject.startsWith(prefix) || prefix.startsWith(subject);
		}
		return false;
	}

	return matches(a, b) || matches(b, a);
}

function actionsHaveWriteIntent(actions: string[]): boolean {
	return actions.some((a) => ["write", "delete", "update", "create", "execute"].includes(a));
}

function actionsAreReadOnly(actions: string[]): boolean {
	const nonRead = actions.filter((a) => !["read", "list"].includes(a));
	return nonRead.length === 0;
}

function requiresApproval(constraints: Record<string, unknown>): boolean {
	return constraints.requireApproval === true;
}

function detectConflicts(
	current: { resource: string; actions: string[]; constraints: Record<string, unknown> },
	existing: PermissionTemplate[],
	editingId?: string,
): ConflictResult[] {
	const results: ConflictResult[] = [];

	for (const tpl of existing) {
		// Skip the template being edited (comparing against itself)
		if (editingId !== undefined && tpl.id === editingId) continue;
		if (!patternsOverlap(current.resource, tpl.resource)) continue;

		const currentWritable = actionsHaveWriteIntent(current.actions);
		const tplWritable = actionsHaveWriteIntent(tpl.actions);
		const currentReadOnly = actionsAreReadOnly(current.actions);
		const tplReadOnly = actionsAreReadOnly(tpl.actions);

		// Contradiction: one template requires approval, the other doesn't, on the same resource
		const currentApproval = requiresApproval(current.constraints);
		const tplApproval = requiresApproval(tpl.constraints);
		if (currentApproval !== tplApproval) {
			results.push({
				kind: "contradiction",
				otherName: tpl.name,
				message: `Contradicts "${tpl.name}": one requires human approval on overlapping resource "${tpl.resource}", the other does not.`,
			});
		}

		// Redundancy: current is fully covered by a broader template with the same or superset of actions
		if (
			patternsOverlap(current.resource, tpl.resource) &&
			(tpl.resource === "*" ||
				(tpl.resource.endsWith("*") && current.resource.startsWith(tpl.resource.slice(0, -1)))) &&
			tpl.actions.length >= current.actions.length &&
			current.actions.every((a) => tpl.actions.includes(a))
		) {
			results.push({
				kind: "redundancy",
				otherName: tpl.name,
				message: `Redundant with "${tpl.name}": that template already covers "${tpl.resource}" with the same or broader actions.`,
			});
			continue; // No need to also flag an overlap for the same pair
		}

		// Overlap: one read-only, other has write access on matching resources
		if (currentReadOnly && tplWritable) {
			results.push({
				kind: "overlap",
				otherName: tpl.name,
				message: `Overlaps with "${tpl.name}": this template is read-only but "${tpl.name}" grants write access on matching resource "${tpl.resource}".`,
			});
		} else if (currentWritable && tplReadOnly) {
			results.push({
				kind: "overlap",
				otherName: tpl.name,
				message: `Overlaps with "${tpl.name}": this template grants write access while "${tpl.name}" is read-only on matching resource "${tpl.resource}".`,
			});
		}
	}

	return results;
}

// Component

export interface ConflictWarningProps {
	resource: string;
	actions: string[];
	constraints: Record<string, unknown>;
	allTemplates: PermissionTemplate[];
	/** ID of the template being edited, so we skip self-comparison */
	editingId?: string;
}

export function ConflictWarning({
	resource,
	actions,
	constraints,
	allTemplates,
	editingId,
}: ConflictWarningProps) {
	if (!resource.trim() || actions.length === 0) return null;

	const conflicts = detectConflicts({ resource, actions, constraints }, allTemplates, editingId);
	if (conflicts.length === 0) return null;

	return (
		<div
			className="rounded-lg border border-yellow-700/60 bg-yellow-950/30 px-3.5 py-3"
			role="alert"
			aria-live="polite"
		>
			<div className="flex items-start gap-2.5">
				<AlertTriangle className="w-4 h-4 text-yellow-500 mt-0.5 flex-shrink-0" />
				<div className="min-w-0">
					<p className="text-xs font-semibold text-yellow-400 mb-1.5">
						{conflicts.length === 1
							? "Potential conflict detected"
							: `${conflicts.length} potential conflicts detected`}
					</p>
					<ul className="space-y-1">
						{conflicts.map((c) => (
							<li
								key={`${c.kind}-${c.otherName}-${c.message}`}
								className="text-[11px] text-yellow-300/80 leading-relaxed"
							>
								<span className="inline-block w-16 font-mono text-yellow-600 uppercase tracking-wide text-[9px]">
									{c.kind}
								</span>
								{c.message}
							</li>
						))}
					</ul>
				</div>
			</div>
		</div>
	);
}
