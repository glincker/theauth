/** Subject identifier validation, canonical keys and matching (RFC 9493). */

import type { ComplexMember, SimpleSubject, SubjectIdentifier } from "./types.js";
import { COMPLEX_MEMBERS } from "./types.js";

const MAX_FIELD = 2048;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function str(value: unknown): string | null {
	return typeof value === "string" && value.length > 0 && value.length <= MAX_FIELD ? value : null;
}

function parseSimple(raw: unknown): SimpleSubject | null {
	if (!isRecord(raw)) return null;
	switch (raw.format) {
		case "iss_sub": {
			const iss = str(raw.iss);
			const sub = str(raw.sub);
			return iss && sub ? { format: "iss_sub", iss, sub } : null;
		}
		case "email": {
			const email = str(raw.email);
			return email?.includes("@") ? { format: "email", email } : null;
		}
		case "opaque": {
			const id = str(raw.id);
			return id ? { format: "opaque", id } : null;
		}
		default:
			return null;
	}
}

/** Validate untrusted input into a subject identifier. Returns null when invalid. */
export function parseSubject(raw: unknown): SubjectIdentifier | null {
	if (!isRecord(raw)) return null;
	if (raw.format !== "complex") return parseSimple(raw);
	const out: Record<string, unknown> = { format: "complex" };
	let members = 0;
	for (const member of COMPLEX_MEMBERS) {
		const value = raw[member];
		if (value === undefined) continue;
		const parsed = parseSimple(value);
		if (!parsed) return null;
		out[member] = parsed;
		members += 1;
	}
	if (members === 0) return null;
	return out as unknown as SubjectIdentifier;
}

function simpleKey(subject: SimpleSubject): string {
	switch (subject.format) {
		case "iss_sub":
			return JSON.stringify(["iss_sub", subject.iss, subject.sub]);
		case "email":
			return JSON.stringify(["email", subject.email.toLowerCase()]);
		case "opaque":
			return JSON.stringify(["opaque", subject.id]);
	}
}

/** Stable key used to store and compare subjects. Email compares case-insensitively. */
export function subjectKey(subject: SubjectIdentifier): string {
	if (subject.format !== "complex") return simpleKey(subject);
	const parts: string[] = [];
	for (const member of COMPLEX_MEMBERS) {
		const value = subject[member];
		if (value) parts.push(`${member}=${simpleKey(value)}`);
	}
	return `complex:${parts.join("&")}`;
}

/**
 * Keys a stream's subject list is checked against for an event subject: the subject itself, plus each member of a complex subject, so a stream that follows a user also sees that user's session and device events.
 */
export function candidateKeys(subject: SubjectIdentifier): string[] {
	const keys = [subjectKey(subject)];
	if (subject.format === "complex") {
		for (const member of COMPLEX_MEMBERS) {
			const value: SimpleSubject | undefined = subject[member as ComplexMember];
			if (value) keys.push(simpleKey(value));
		}
	}
	return keys;
}
