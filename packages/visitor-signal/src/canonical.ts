import type { Components } from "./types.js";

type Json = string | number | boolean | null | Json[] | { [k: string]: Json | undefined };

const ser = (v: Json | undefined): string | undefined => {
	if (v === undefined) return undefined;
	if (v === null) return "null";
	if (Array.isArray(v)) return `[${v.map((x) => ser(x) ?? "null").join(",")}]`;
	if (typeof v === "object") {
		// Default sort compares UTF-16 code units, which is what JCS requires.
		const parts: string[] = [];
		for (const k of Object.keys(v).sort()) {
			const s = ser(v[k]);
			if (s !== undefined) parts.push(`${JSON.stringify(k)}:${s}`);
		}
		return `{${parts.join(",")}}`;
	}
	return JSON.stringify(v);
};

/** RFC 8785 style serialisation of one value. Absent (undefined) keys are omitted. */
export const canonicalValue = (v: Json): string => ser(v) ?? "null";

export const canonicalise = (components: Components): string =>
	canonicalValue(components as { [k: string]: Json | undefined });
