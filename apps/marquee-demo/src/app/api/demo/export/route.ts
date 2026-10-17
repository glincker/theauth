/**
 * POST /api/demo/export (step 5): exports the audit trail as a signed JSON file.
 * TODO(v3): replace signedExport() with exportAuditAsVC once the vc/audit-export PR merges.
 */

import { NextResponse } from "next/server";
import { getSessionId } from "@/lib/cookie";
import { getSession, setSession } from "@/lib/session-store";

interface AuditExportPayload {
	"@context": string[];
	type: string;
	issuer: string;
	issuanceDate: string;
	credentialSubject: {
		agentId: string | null;
		userId: string;
		toolCalls: unknown[];
		auditLog: unknown[];
		regulation: string;
		exportedAt: string;
	};
	proof: {
		type: string;
		created: string;
		note: string;
	};
}

function buildSignedExport(
	agentId: string | null,
	userId: string,
	toolCalls: unknown[],
	auditLog: unknown[],
): AuditExportPayload {
	const now = new Date().toISOString();

	return {
		"@context": ["https://www.w3.org/2018/credentials/v1", "https://theauth.dev/contexts/audit/v1"],
		type: "TheAuthAuditCredential",
		issuer: "https://theauth.dev",
		issuanceDate: now,
		credentialSubject: {
			agentId,
			userId,
			toolCalls,
			auditLog,
			regulation: "EU AI Act, Article 12 (record-keeping)",
			exportedAt: now,
		},
		proof: {
			type: "TheAuthSimulatedProof",
			created: now,
			// TODO(v3): swap for a real Ed25519Signature2020 once exportAuditAsVC lands.
			note: "Proof stub, full VC signing ships in v3/vc-audit-export PR",
		},
	};
}

export async function POST(): Promise<NextResponse> {
	try {
		const sessionId = await getSessionId();
		if (!sessionId) {
			return NextResponse.json({ error: "No session cookie" }, { status: 401 });
		}

		const session = getSession(sessionId);
		if (!session?.delegationDone) {
			return NextResponse.json({ error: "Complete step 4 first" }, { status: 400 });
		}

		const payload = buildSignedExport(
			session.agentId,
			session.userId,
			session.toolCalls.map((c) => ({
				tool: c.tool,
				input: c.input,
				output: c.output,
				timestamp: c.timestamp.toISOString(),
				auditId: c.auditId,
			})),
			session.auditLog.map((e) => ({
				id: e.id,
				action: e.action,
				resource: e.resource,
				result: e.result,
				timestamp: e.timestamp.toISOString(),
				durationMs: e.durationMs,
			})),
		);

		session.exportReady = true;
		setSession(sessionId, session);

		const json = JSON.stringify(payload, null, 2);
		const bytes = new TextEncoder().encode(json);

		return new NextResponse(bytes, {
			status: 200,
			headers: {
				"Content-Type": "application/json",
				"Content-Disposition": 'attachment; filename="theauth-audit-export.json"',
			},
		});
	} catch (err) {
		return NextResponse.json(
			{ error: err instanceof Error ? err.message : "Unknown error" },
			{ status: 500 },
		);
	}
}
