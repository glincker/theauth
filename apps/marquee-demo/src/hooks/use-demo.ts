"use client";

import { useCallback, useEffect, useRef, useState } from "react";

interface AuditEntry {
	id: string;
	action: string;
	resource: string;
	result: string;
	timestamp: string;
	durationMs: number;
}

interface DemoState {
	step: number;
	userId: string | null;
	userName: string | null;
	agentId: string | null;
	agentName: string | null;
	subAgentId: string | null;
	subAgentName: string | null;
	toolCallsComplete: number;
	delegationDone: boolean;
	exportReady: boolean;
	auditLog: AuditEntry[];
}

interface StepResult {
	success: boolean;
	[key: string]: unknown;
}

const INITIAL: DemoState = {
	step: 0,
	userId: null,
	userName: null,
	agentId: null,
	agentName: null,
	subAgentId: null,
	subAgentName: null,
	toolCallsComplete: 0,
	delegationDone: false,
	exportReady: false,
	auditLog: [],
};

export function useDemo() {
	const [state, setState] = useState<DemoState>(INITIAL);
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [lastResult, setLastResult] = useState<StepResult | null>(null);
	const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

	const fetchState = useCallback(async () => {
		try {
			const res = await fetch("/api/demo/state");
			if (!res.ok) return;
			const data = (await res.json()) as DemoState;
			setState(data);
		} catch {
			// Silently ignore poll failures
		}
	}, []);

	useEffect(() => {
		void fetchState();
		pollRef.current = setInterval(() => void fetchState(), 2000);
		return () => {
			if (pollRef.current) clearInterval(pollRef.current);
		};
	}, [fetchState]);

	async function callApi(path: string, body?: unknown): Promise<StepResult | null> {
		setLoading(true);
		setError(null);
		try {
			const res = await fetch(path, {
				method: "POST",
				headers: body ? { "Content-Type": "application/json" } : {},
				body: body ? JSON.stringify(body) : undefined,
			});
			const data = (await res.json()) as StepResult;
			if (!res.ok) {
				setError((data as { error?: string }).error ?? "Request failed");
				return null;
			}
			setLastResult(data);
			await fetchState();
			return data;
		} catch (err) {
			setError(err instanceof Error ? err.message : "Network error");
			return null;
		} finally {
			setLoading(false);
		}
	}

	async function signup(userName: string): Promise<StepResult | null> {
		return callApi("/api/demo/signup", { userName });
	}

	async function spawnAgent(): Promise<StepResult | null> {
		return callApi("/api/demo/spawn-agent");
	}

	async function toolCall(): Promise<StepResult | null> {
		return callApi("/api/demo/tool-call");
	}

	async function delegate(): Promise<StepResult | null> {
		return callApi("/api/demo/delegate");
	}

	async function exportAudit(): Promise<void> {
		setLoading(true);
		setError(null);
		try {
			const res = await fetch("/api/demo/export", { method: "POST" });
			if (!res.ok) {
				const data = (await res.json()) as { error?: string };
				setError(data.error ?? "Export failed");
				return;
			}
			const blob = await res.blob();
			const url = URL.createObjectURL(blob);
			const a = document.createElement("a");
			a.href = url;
			a.download = "theauth-audit-export.json";
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			URL.revokeObjectURL(url);
			await fetchState();
		} catch (err) {
			setError(err instanceof Error ? err.message : "Network error");
		} finally {
			setLoading(false);
		}
	}

	async function reset(): Promise<void> {
		setLoading(true);
		try {
			await fetch("/api/demo/reset", { method: "POST" });
			setState(INITIAL);
			setLastResult(null);
			setError(null);
		} finally {
			setLoading(false);
		}
	}

	return {
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
	};
}
