import { json } from "../plugin/helpers.js";
import { asId, isRecord } from "./validate.js";

export function fail(status: number, code: string, message: string): Response {
	return json({ error: { code, message } }, status);
}

function lastSegments(request: Request): string[] {
	return new URL(request.url).pathname.split("/").filter(Boolean);
}

export function pathId(request: Request, fromEnd: number): string | undefined {
	const seg = lastSegments(request);
	const raw = seg[seg.length - 1 - fromEnd];
	if (raw === undefined) return undefined;
	try {
		return asId(decodeURIComponent(raw));
	} catch {
		return undefined;
	}
}

export async function readObject(request: Request): Promise<Record<string, unknown> | undefined> {
	try {
		const body: unknown = await request.json();
		return isRecord(body) ? body : undefined;
	} catch {
		return undefined;
	}
}
