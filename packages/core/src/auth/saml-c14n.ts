/**
 * Exclusive XML Canonicalization 1.0 (with and without comments) over the parsed tree.
 * https://www.w3.org/TR/xml-exc-c14n/
 * Works on an element subtree (the document subset for a same-document reference) and can omit one
 * descendant element, which is how the enveloped-signature transform is applied: structurally, never by text matching.
 */

import type { XmlAttr, XmlNode } from "./sso-types.js";

export const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
export const EXC_C14N_WITH_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

export interface C14nOptions {
	/** Keep comments (the #WithComments variant). */
	withComments?: boolean;
	/** InclusiveNamespaces PrefixList. "#default" means the default namespace. */
	inclusivePrefixes?: readonly string[];
	/** An element left out of the output together with its subtree (enveloped-signature). */
	exclude?: XmlNode | null;
}

function escapeText(v: string): string {
	let out = "";
	for (const ch of v) {
		if (ch === "&") out += "&amp;";
		else if (ch === "<") out += "&lt;";
		else if (ch === ">") out += "&gt;";
		else if (ch === "\r") out += "&#xD;";
		else out += ch;
	}
	return out;
}

function escapeAttr(v: string): string {
	let out = "";
	for (const ch of v) {
		if (ch === "&") out += "&amp;";
		else if (ch === "<") out += "&lt;";
		else if (ch === '"') out += "&quot;";
		else if (ch === "\t") out += "&#x9;";
		else if (ch === "\n") out += "&#xA;";
		else if (ch === "\r") out += "&#xD;";
		else out += ch;
	}
	return out;
}

function compareCodePoints(a: string, b: string): number {
	if (a === b) return 0;
	return a < b ? -1 : 1;
}

function compareAttrs(a: XmlAttr, b: XmlAttr): number {
	return (
		compareCodePoints(a.namespaceURI, b.namespaceURI) || compareCodePoints(a.localName, b.localName)
	);
}

/** Namespace declarations to emit on `el`, given what output ancestors already rendered. */
function namespacesToRender(
	el: XmlNode,
	rendered: ReadonlyMap<string, string>,
	inclusive: ReadonlySet<string>,
): Array<[string, string]> {
	const candidates = new Set<string>([el.prefix]);
	for (const a of el.attrs) {
		if (a.prefix && a.prefix !== "xml") candidates.add(a.prefix);
	}
	for (const p of inclusive) {
		if (p === "" || el.inScopeNs.has(p)) candidates.add(p);
	}
	const out: Array<[string, string]> = [];
	for (const p of candidates) {
		if (p === "xml") continue;
		const uri = el.inScopeNs.get(p) ?? "";
		const current = rendered.get(p) ?? "";
		if (p === "") {
			if (uri !== current) out.push(["", uri]);
		} else if (!rendered.has(p) || current !== uri) {
			out.push([p, uri]);
		}
	}
	out.sort((a, b) => compareCodePoints(a[0], b[0]));
	return out;
}

function render(
	el: XmlNode,
	rendered: ReadonlyMap<string, string>,
	opts: C14nOptions,
	inclusive: ReadonlySet<string>,
	parts: string[],
): void {
	const decls = namespacesToRender(el, rendered, inclusive);
	let scope = rendered;
	if (decls.length > 0) {
		const next = new Map(rendered);
		for (const [p, uri] of decls) next.set(p, uri);
		scope = next;
	}
	parts.push(`<${el.tagName}`);
	for (const [p, uri] of decls) {
		parts.push(p === "" ? ` xmlns="${escapeAttr(uri)}"` : ` xmlns:${p}="${escapeAttr(uri)}"`);
	}
	const attrs = [...el.attrs].sort(compareAttrs);
	for (const a of attrs) parts.push(` ${a.name}="${escapeAttr(a.value)}"`);
	parts.push(">");
	for (const c of el.content) {
		if (c.kind === "element") {
			if (c.node !== opts.exclude) render(c.node, scope, opts, inclusive, parts);
		} else if (c.kind === "text") {
			parts.push(escapeText(c.value));
		} else if (c.kind === "comment") {
			if (opts.withComments) parts.push(`<!--${c.value}-->`);
		} else {
			parts.push(c.value ? `<?${c.target} ${c.value}?>` : `<?${c.target}?>`);
		}
	}
	parts.push(`</${el.tagName}>`);
}

/** Canonicalizes `el` and its subtree with Exclusive XML Canonicalization 1.0. */
export function excC14n(el: XmlNode, opts: C14nOptions = {}): string {
	const inclusive = new Set<string>();
	for (const p of opts.inclusivePrefixes ?? []) inclusive.add(p === "#default" ? "" : p);
	const parts: string[] = [];
	render(el, new Map<string, string>(), opts, inclusive, parts);
	return parts.join("");
}

/** Parses an InclusiveNamespaces PrefixList attribute value. */
export function parsePrefixList(value: string | undefined): string[] {
	if (!value) return [];
	return value.split(/[ \t\n\r]+/).filter((p) => p.length > 0);
}
