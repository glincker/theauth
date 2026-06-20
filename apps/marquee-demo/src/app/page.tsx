"use client";

import { useState } from "react";
import { AuditPanel } from "@/components/audit-panel";
import { CheckBadge } from "@/components/check-badge";
import { CodeBlock } from "@/components/code-block";
import { Collapsible } from "@/components/collapsible";
import { useDemo } from "@/hooks/use-demo";

export default function DemoPage() {
	const {
		state,
		loading,
		error,
		lastResult,
		signup,
		spawnAgent,
		toolCall,
		delegate,
		exportAudit,
		reset,
	} = useDemo();
	const [userName, setUserName] = useState("");

	const step = state.step;

	return (
		<div className="min-h-screen bg-zinc-950 text-zinc-100">
			{/* Header */}
			<header className="sticky top-0 z-50 border-b border-zinc-800 bg-zinc-950/80 backdrop-blur-sm">
				<div className="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between">
					<div className="flex items-center gap-3">
						<span className="text-brand font-bold text-lg tracking-tight">TheAuth</span>
						<span className="text-zinc-500 text-sm">live demo</span>
					</div>
					<button
						type="button"
						onClick={() => void reset()}
						disabled={loading}
						data-testid="reset-button"
						className="text-xs px-3 py-1.5 rounded-md border border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-zinc-200 transition-colors disabled:opacity-40"
					>
						Reset demo
					</button>
				</div>
			</header>

			<main className="max-w-5xl mx-auto px-4 py-12 space-y-6">
				<div className="text-center mb-10">
					<h1 className="text-3xl font-semibold text-zinc-100 mb-2">
						Agent auth in under 30 seconds
					</h1>
					<p className="text-zinc-400 text-base max-w-2xl mx-auto">
						Each panel runs real TheAuth, passkey sign-up, scoped agent spawning, live tool
						authorization with audit, delegation, and an EU AI Act export.
					</p>
				</div>

				{/* Error banner */}
				{error && (
					<div className="px-4 py-3 rounded-lg bg-red-950/40 border border-red-800/60 text-red-300 text-sm">
						{error}
					</div>
				)}

				{/* Step 1, Sign up */}
				<Panel
					number={1}
					title="Sign up with passkey"
					description="Register a simulated WebAuthn passkey. On a real device this calls navigator.credentials.create()."
					done={step >= 1}
					active={step === 0}
				>
					<div className="flex gap-2">
						<input
							type="text"
							value={userName}
							onChange={(e) => setUserName(e.target.value)}
							placeholder="Your name"
							disabled={step >= 1 || loading}
							data-testid="username-input"
							className="flex-1 px-3 py-2 rounded-md bg-zinc-900 border border-zinc-700 text-zinc-100 text-sm placeholder-zinc-600 focus:outline-none focus:border-brand disabled:opacity-40"
						/>
						<ActionButton
							onClick={() => void signup(userName || "Demo User")}
							disabled={step >= 1 || loading}
							testId="signup-button"
						>
							Register passkey
						</ActionButton>
					</div>
					{step >= 1 && (
						<p className="text-sm text-emerald-400 mt-2">
							Signed in as <strong>{state.userName}</strong>
						</p>
					)}
					{step >= 1 && lastResult && step === 1 && (
						<Collapsible label="What happened under the hood">
							<div className="space-y-2 p-0">
								<SectionLabel>API request</SectionLabel>
								<CodeBlock value={(lastResult as { apiRequest?: unknown }).apiRequest} />
								<SectionLabel>Token payload</SectionLabel>
								<CodeBlock value={(lastResult as { tokenPayload?: unknown }).tokenPayload} />
							</div>
						</Collapsible>
					)}
				</Panel>

				{/* Step 2, Spawn agent */}
				<Panel
					number={2}
					title="Spawn an agent"
					description="Create a TheAuth agent with read-only access to the calendar tool surface."
					done={step >= 2}
					active={step === 1}
				>
					<ActionButton
						onClick={() => void spawnAgent()}
						disabled={step !== 1 || loading}
						testId="spawn-agent-button"
					>
						Spawn calendar-reader agent
					</ActionButton>
					{step >= 2 && (
						<p className="text-sm text-emerald-400 mt-2">
							Agent <code className="font-mono text-brand">{state.agentName}</code> is active
						</p>
					)}
					{step >= 2 && lastResult && step === 2 && (
						<Collapsible label="What happened under the hood">
							<SectionLabel>API request</SectionLabel>
							<CodeBlock value={(lastResult as { apiRequest?: unknown }).apiRequest} />
							<SectionLabel>Agent token payload</SectionLabel>
							<CodeBlock value={(lastResult as { tokenPayload?: unknown }).tokenPayload} />
						</Collapsible>
					)}
				</Panel>

				{/* Step 3, Tool calls + audit */}
				<Panel
					number={3}
					title="Make tool calls"
					description="The agent calls three calendar tools. Each call goes through TheAuth authorization and is written to the audit log."
					done={step >= 3}
					active={step === 2}
				>
					<div className="flex items-center gap-3 mb-4">
						<ActionButton
							onClick={() => void toolCall()}
							disabled={step < 2 || step >= 3 || loading}
							testId="tool-call-button"
						>
							{state.toolCallsComplete < 3
								? `Run call ${state.toolCallsComplete + 1} of 3`
								: "All calls done"}
						</ActionButton>
						<span className="text-zinc-500 text-sm">{state.toolCallsComplete}/3 complete</span>
					</div>

					<div className="mt-2">
						<p className="text-xs text-zinc-500 mb-2 uppercase tracking-wider">Audit log (live)</p>
						<AuditPanel entries={state.auditLog} />
					</div>

					{step >= 3 && lastResult && (
						<Collapsible label="What happened under the hood">
							<SectionLabel>Authorization request</SectionLabel>
							<CodeBlock value={(lastResult as { apiRequest?: unknown }).apiRequest} />
							<SectionLabel>Authorization result</SectionLabel>
							<CodeBlock value={(lastResult as { authResult?: unknown }).authResult} />
						</Collapsible>
					)}
				</Panel>

				{/* Step 4, Delegation */}
				<Panel
					number={4}
					title="Delegate to a sub-agent"
					description="The calendar-reader delegates to a narrower sub-agent that can only list events, not read free/busy data."
					done={step >= 4}
					active={step === 3}
				>
					<ActionButton
						onClick={() => void delegate()}
						disabled={step !== 3 || loading}
						testId="delegate-button"
					>
						Delegate to standup-reader
					</ActionButton>
					{step >= 4 && (
						<p className="text-sm text-emerald-400 mt-2">
							Sub-agent <code className="font-mono text-brand">{state.subAgentName}</code> created
						</p>
					)}
					{step >= 4 && lastResult && step === 4 && (
						<Collapsible label="What happened under the hood">
							<SectionLabel>Delegation chain</SectionLabel>
							<CodeBlock value={(lastResult as { delegationChain?: unknown }).delegationChain} />
							<SectionLabel>Sub-agent token payload</SectionLabel>
							<CodeBlock value={(lastResult as { tokenPayload?: unknown }).tokenPayload} />
						</Collapsible>
					)}
				</Panel>

				{/* Step 5, Export */}
				<Panel
					number={5}
					title="Export audit trail"
					description="Download the full audit trail as a signed JSON file formatted for EU AI Act Article 12 record-keeping."
					done={step >= 5}
					active={step === 4}
				>
					<ActionButton
						onClick={() => void exportAudit()}
						disabled={step < 4 || loading}
						testId="export-button"
					>
						Download EU AI Act report
					</ActionButton>
					{step >= 5 && (
						<p className="text-sm text-emerald-400 mt-2">
							Report downloaded. Reset the demo to start again.
						</p>
					)}
					<p className="text-xs text-zinc-600 mt-3">
						Full W3C Verifiable Credential signing (Ed25519Signature2020) ships in the upcoming
						vc-audit-export release.
					</p>
				</Panel>
			</main>
		</div>
	);
}

// ── Sub-components ────────────────────────────────────────────────────────────

interface PanelProps {
	number: number;
	title: string;
	description: string;
	done: boolean;
	active: boolean;
	children: React.ReactNode;
}

function Panel({ number, title, description, done, active, children }: PanelProps) {
	return (
		<section
			data-testid={`panel-${number}`}
			data-done={done ? "true" : "false"}
			className={[
				"rounded-xl border p-6 transition-colors",
				done
					? "border-emerald-800/60 bg-emerald-950/10"
					: active
						? "border-brand/40 bg-zinc-900/60"
						: "border-zinc-800 bg-zinc-900/30 opacity-60",
			].join(" ")}
		>
			<div className="flex items-center gap-3 mb-1">
				<span className="flex items-center justify-center w-7 h-7 rounded-full border border-zinc-700 text-zinc-400 text-xs font-bold shrink-0">
					{number}
				</span>
				<h2 className="text-base font-semibold text-zinc-100">{title}</h2>
				<CheckBadge done={done} />
			</div>
			<p className="text-sm text-zinc-500 mb-4 ml-10">{description}</p>
			<div className="ml-10">{children}</div>
		</section>
	);
}

interface ActionButtonProps {
	onClick: () => void;
	disabled: boolean;
	testId: string;
	children: React.ReactNode;
}

function ActionButton({ onClick, disabled, testId, children }: ActionButtonProps) {
	return (
		<button
			type="button"
			onClick={onClick}
			disabled={disabled}
			data-testid={testId}
			className="px-4 py-2 rounded-lg bg-brand text-zinc-950 text-sm font-semibold hover:bg-brand-light transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
		>
			{children}
		</button>
	);
}

function SectionLabel({ children }: { children: React.ReactNode }) {
	return (
		<p className="text-xs text-zinc-500 uppercase tracking-wider px-4 pt-3 pb-1">{children}</p>
	);
}
