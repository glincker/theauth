/**
 * Strict, namespace-aware XML parser for SAML responses.
 * Rejects DOCTYPE, ENTITY, unknown entity references and illegal characters; enforces size, depth, attribute and element limits.
 * Keeps mixed content (text, comments, processing instructions) so the canonicalizer can work on the parsed tree.
 */

import type { XmlAttr, XmlChild, XmlLimits, XmlNode } from "./sso-types.js";
import { SSO_ERROR, SsoError } from "./sso-types.js";

export const XML_NS = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS = "http://www.w3.org/2000/xmlns/";

export const DEFAULT_XML_LIMITS: XmlLimits = {
	maxBytes: 262_144,
	maxDepth: 32,
	maxAttributes: 32,
	maxElements: 4096,
};

const NAME_RE = /^[A-Za-z_][A-Za-z0-9._-]*(?::[A-Za-z_][A-Za-z0-9._-]*)?$/;
// Characters not allowed in XML 1.0 documents (after line-end normalization).
// biome-ignore lint/suspicious/noControlCharactersInRegex: matching control characters is the point
const ILLEGAL_CHAR_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]/;

function fail(message: string): never {
	throw new SsoError(SSO_ERROR.SAML_XML_PARSE_ERROR, message);
}

function limit(message: string): never {
	throw new SsoError(SSO_ERROR.SAML_XML_LIMIT_EXCEEDED, message);
}

/** Rejects XXE vectors (DOCTYPE, ENTITY, NUL character references). SAML responses never need them. */
export function checkXxe(xml: string): void {
	if (/<!DOCTYPE/i.test(xml)) {
		throw new SsoError(
			SSO_ERROR.SAML_XXE_DETECTED,
			"XML contains DOCTYPE declaration which is not allowed in SAML responses",
		);
	}
	if (/<!ENTITY/i.test(xml)) {
		throw new SsoError(
			SSO_ERROR.SAML_XXE_DETECTED,
			"XML contains ENTITY declaration which is not allowed in SAML responses",
		);
	}
	if (/&#x0*0;|&#0*0;/i.test(xml)) {
		throw new SsoError(SSO_ERROR.SAML_XXE_DETECTED, "XML contains null character entity reference");
	}
}

/** Removes comments from raw XML. Legacy helper; the parser itself keeps comments as nodes. */
export function stripXmlComments(xml: string): string {
	let result = "";
	let i = 0;
	while (i < xml.length) {
		if (xml.startsWith("<!--", i)) {
			const endIdx = xml.indexOf("-->", i + 4);
			if (endIdx === -1) fail("Unterminated XML comment");
			i = endIdx + 3;
		} else {
			result += xml[i];
			i++;
		}
	}
	return result;
}

function decodeCharRef(body: string): string {
	const hex = body.startsWith("#x");
	const digits = body.slice(hex ? 2 : 1);
	if (!(hex ? /^[0-9A-Fa-f]{1,6}$/ : /^[0-9]{1,7}$/).test(digits))
		fail(`Bad character reference &${body};`);
	const cp = Number.parseInt(digits, hex ? 16 : 10);
	const legal =
		cp === 0x9 ||
		cp === 0xa ||
		cp === 0xd ||
		(cp >= 0x20 && cp <= 0xd7ff) ||
		(cp >= 0xe000 && cp <= 0xfffd) ||
		(cp >= 0x10000 && cp <= 0x10ffff);
	if (!legal) fail(`Character reference &${body}; is not a legal XML character`);
	return String.fromCodePoint(cp);
}

/** Decodes the five predefined entities and character references. Anything else is rejected. */
function decodeEntities(raw: string, inAttribute: boolean): string {
	let out = "";
	let i = 0;
	while (i < raw.length) {
		const ch = raw[i] as string;
		if (ch === "&") {
			const end = raw.indexOf(";", i);
			if (end === -1 || end - i > 12) fail("Unterminated entity reference");
			const body = raw.slice(i + 1, end);
			if (body === "amp") out += "&";
			else if (body === "lt") out += "<";
			else if (body === "gt") out += ">";
			else if (body === "quot") out += '"';
			else if (body === "apos") out += "'";
			else if (body.startsWith("#")) out += decodeCharRef(body);
			else fail(`Unknown entity reference &${body};`);
			i = end + 1;
			continue;
		}
		if (inAttribute && (ch === "\t" || ch === "\n")) out += " ";
		else out += ch;
		i++;
	}
	return out;
}

interface RawElement {
	tagName: string;
	rawAttrs: Array<[string, string]>;
	selfClosing: boolean;
	end: number;
}

interface ParserState {
	src: string;
	pos: number;
	elements: number;
	limits: XmlLimits;
}

function skipMisc(st: ParserState): void {
	for (;;) {
		while (st.pos < st.src.length && /\s/.test(st.src[st.pos] as string)) st.pos++;
		if (st.src.startsWith("<!--", st.pos)) readComment(st);
		else if (st.src.startsWith("<?", st.pos)) readPi(st);
		else if (st.src.startsWith("<!", st.pos)) fail("Markup declarations are not allowed");
		else return;
	}
}

function skipProlog(st: ParserState): void {
	if (st.src.charCodeAt(0) === 0xfeff) st.pos = 1;
	if (st.src.startsWith("<?xml", st.pos) && /\s/.test(st.src[st.pos + 5] ?? "")) {
		const end = st.src.indexOf("?>", st.pos);
		if (end === -1) fail("Unterminated XML declaration");
		const decl = st.src.slice(st.pos, end);
		const enc = /encoding\s*=\s*["']([^"']+)["']/.exec(decl);
		if (enc && enc[1]?.toUpperCase() !== "UTF-8") {
			fail("Only UTF-8 encoded SAML responses are supported");
		}
		st.pos = end + 2;
	}
	skipMisc(st);
}

function readComment(st: ParserState): string {
	const end = st.src.indexOf("-->", st.pos + 4);
	if (end === -1) fail("Unterminated XML comment");
	const value = st.src.slice(st.pos + 4, end);
	if (value.includes("--") || value.endsWith("-")) fail("Malformed XML comment");
	st.pos = end + 3;
	return value;
}

function readPi(st: ParserState): { target: string; value: string } {
	const end = st.src.indexOf("?>", st.pos + 2);
	if (end === -1) fail("Unterminated processing instruction");
	const body = st.src.slice(st.pos + 2, end);
	const m = /^([A-Za-z_][A-Za-z0-9._:-]*)(?:\s+([\s\S]*))?$/.exec(body);
	if (!m || m[1]?.toLowerCase() === "xml") fail("Malformed processing instruction");
	st.pos = end + 2;
	return { target: m[1] as string, value: m[2] ?? "" };
}

function readStartTag(st: ParserState): RawElement {
	const s = st.src;
	let i = st.pos + 1;
	const nameStart = i;
	while (i < s.length && !/[\s/>]/.test(s[i] as string)) i++;
	const tagName = s.slice(nameStart, i);
	if (!NAME_RE.test(tagName)) fail(`Invalid element name "${tagName.slice(0, 40)}"`);
	const rawAttrs: Array<[string, string]> = [];
	for (;;) {
		const wsStart = i;
		while (i < s.length && /\s/.test(s[i] as string)) i++;
		if (s[i] === ">") return { tagName, rawAttrs, selfClosing: false, end: i + 1 };
		if (s[i] === "/" && s[i + 1] === ">") {
			return { tagName, rawAttrs, selfClosing: true, end: i + 2 };
		}
		if (i >= s.length) fail(`Unterminated start tag <${tagName}>`);
		if (i === wsStart) fail(`Missing whitespace between attributes in <${tagName}>`);
		const an = i;
		while (i < s.length && !/[\s=/>]/.test(s[i] as string)) i++;
		const attrName = s.slice(an, i);
		if (!NAME_RE.test(attrName)) fail(`Invalid attribute name in <${tagName}>`);
		while (i < s.length && /\s/.test(s[i] as string)) i++;
		if (s[i] !== "=") fail(`Attribute ${attrName} has no value`);
		i++;
		while (i < s.length && /\s/.test(s[i] as string)) i++;
		const quote = s[i];
		if (quote !== '"' && quote !== "'") fail(`Attribute ${attrName} value must be quoted`);
		const close = s.indexOf(quote, i + 1);
		if (close === -1) fail(`Unterminated attribute value for ${attrName}`);
		const rawValue = s.slice(i + 1, close);
		if (rawValue.includes("<")) fail(`Attribute ${attrName} contains "<"`);
		rawAttrs.push([attrName, decodeEntities(rawValue, true)]);
		if (rawAttrs.length > st.limits.maxAttributes) limit(`Too many attributes on <${tagName}>`);
		i = close + 1;
	}
}

function resolveNamespaces(
	raw: RawElement,
	parentNs: ReadonlyMap<string, string>,
): {
	attributes: Map<string, string>;
	nsDecls: Map<string, string>;
	inScopeNs: ReadonlyMap<string, string>;
} {
	const attributes = new Map<string, string>();
	const nsDecls = new Map<string, string>();
	for (const [name, value] of raw.rawAttrs) {
		if (attributes.has(name)) fail(`Duplicate attribute ${name} on <${raw.tagName}>`);
		attributes.set(name, value);
		if (name === "xmlns") {
			if (value === XML_NS || value === XMLNS_NS) fail("Reserved namespace bound to default");
			nsDecls.set("", value);
		} else if (name.startsWith("xmlns:")) {
			const p = name.slice(6);
			if (value === "") fail(`Namespace prefix ${p} cannot be undeclared`);
			if (p === "xmlns" || (p === "xml") !== (value === XML_NS) || value === XMLNS_NS) {
				fail(`Illegal binding for namespace prefix ${p}`);
			}
			nsDecls.set(p, value);
		}
	}
	if (nsDecls.size === 0) return { attributes, nsDecls, inScopeNs: parentNs };
	const m = new Map(parentNs);
	for (const [p, uri] of nsDecls) {
		if (p === "" && uri === "") m.delete("");
		else m.set(p, uri);
	}
	return { attributes, nsDecls, inScopeNs: m };
}

function splitQName(name: string): { prefix: string; localName: string } {
	const c = name.indexOf(":");
	return c === -1
		? { prefix: "", localName: name }
		: { prefix: name.slice(0, c), localName: name.slice(c + 1) };
}

function parseElement(
	st: ParserState,
	parentNs: ReadonlyMap<string, string>,
	depth: number,
): XmlNode {
	if (depth > st.limits.maxDepth) limit("XML nesting is too deep");
	st.elements++;
	if (st.elements > st.limits.maxElements) limit("XML has too many elements");
	const startIdx = st.pos;
	const raw = readStartTag(st);
	st.pos = raw.end;

	const { attributes, nsDecls, inScopeNs } = resolveNamespaces(raw, parentNs);
	const { prefix, localName } = splitQName(raw.tagName);
	if (prefix && !inScopeNs.has(prefix)) fail(`Unbound namespace prefix ${prefix}`);
	const namespaceURI = inScopeNs.get(prefix) ?? "";

	const attrs: XmlAttr[] = [];
	const seen = new Set<string>();
	for (const [name, value] of raw.rawAttrs) {
		if (name === "xmlns" || name.startsWith("xmlns:")) continue;
		const q = splitQName(name);
		if (q.prefix && !inScopeNs.has(q.prefix)) fail(`Unbound namespace prefix ${q.prefix}`);
		const aNs = q.prefix ? (inScopeNs.get(q.prefix) as string) : "";
		const key = `${aNs}|${q.localName}`;
		if (seen.has(key)) fail(`Duplicate attribute ${q.localName} on <${raw.tagName}>`);
		seen.add(key);
		attrs.push({ name, prefix: q.prefix, localName: q.localName, namespaceURI: aNs, value });
	}

	const node: XmlNode = {
		localName,
		prefix,
		tagName: raw.tagName,
		namespaceURI,
		attributes,
		attrs,
		nsDecls,
		inScopeNs,
		children: [],
		content: [],
		textContent: "",
		rawInnerXml: "",
		rawOuterXml: "",
	};
	if (!raw.selfClosing) parseContent(st, node, depth);
	node.rawOuterXml = st.src.slice(startIdx, st.pos);
	return node;
}

function parseContent(st: ParserState, node: XmlNode, depth: number): void {
	const s = st.src;
	const contentStart = st.pos;
	let text = "";
	const content: XmlChild[] = node.content;
	const pushText = (value: string) => {
		const last = content[content.length - 1];
		if (last && last.kind === "text") last.value += value;
		else content.push({ kind: "text", value });
		text += value;
	};
	while (st.pos < s.length) {
		const lt = s.indexOf("<", st.pos);
		if (lt === -1) break;
		if (lt > st.pos) {
			const chunk = s.slice(st.pos, lt);
			if (chunk.includes("]]>")) fail("Literal ]]> in text");
			pushText(decodeEntities(chunk, false));
			st.pos = lt;
		}
		if (s.startsWith("<![CDATA[", lt)) {
			const end = s.indexOf("]]>", lt + 9);
			if (end === -1) fail("Unterminated CDATA section");
			pushText(s.slice(lt + 9, end));
			st.pos = end + 3;
		} else if (s.startsWith("<!--", lt)) {
			content.push({ kind: "comment", value: readComment(st) });
		} else if (s.startsWith("<?", lt)) {
			content.push({ kind: "pi", ...readPi(st) });
		} else if (s.startsWith("<!", lt)) {
			fail("Markup declarations are not allowed");
		} else if (s[lt + 1] === "/") {
			const close = s.indexOf(">", lt);
			if (close === -1) break;
			const closeName = s.slice(lt + 2, close).trimEnd();
			if (closeName !== node.tagName) {
				fail(`Mismatched closing tag: expected </${node.tagName}> but found </${closeName}>`);
			}
			node.rawInnerXml = s.slice(contentStart, lt);
			node.textContent = text.trim();
			st.pos = close + 1;
			return;
		} else {
			const child = parseElement(st, node.inScopeNs, depth + 1);
			node.children.push(child);
			content.push({ kind: "element", node: child });
		}
	}
	fail(`Unterminated element: <${node.tagName}>`);
}

/** Parses XML into an XmlNode tree. Covers the subset of XML found in SAML responses and rejects the rest. */
export function parseXml(xml: string, limits?: Partial<XmlLimits>): XmlNode {
	const l: XmlLimits = { ...DEFAULT_XML_LIMITS, ...limits };
	if (xml.length > l.maxBytes) limit("XML document is too large");
	checkXxe(xml);
	const normalized = xml.replace(/\r\n?/g, "\n");
	if (ILLEGAL_CHAR_RE.test(normalized)) fail("XML contains illegal characters");
	const st: ParserState = { src: normalized, pos: 0, elements: 0, limits: l };
	skipProlog(st);
	if (!st.src.startsWith("<", st.pos)) fail("Failed to parse XML: no root element found");
	const root = parseElement(st, new Map<string, string>([["xml", XML_NS]]), 1);
	skipMisc(st);
	if (st.pos < st.src.length) fail("Content after the root element");
	return root;
}

/** Finds the first descendant with a matching local name (namespace-agnostic). Never used for verified claims. */
export function findElement(node: XmlNode, localName: string): XmlNode | null {
	if (node.localName === localName) return node;
	for (const child of node.children) {
		const found = findElement(child, localName);
		if (found) return found;
	}
	return null;
}

/** Finds all descendants with a matching local name. */
export function findAllElements(node: XmlNode, localName: string): XmlNode[] {
	const results: XmlNode[] = [];
	if (node.localName === localName) results.push(node);
	for (const child of node.children) {
		results.push(...findAllElements(child, localName));
	}
	return results;
}

/** Returns a descendant element's text content by local name. */
export function getElementText(node: XmlNode, localName: string): string | null {
	const el = findElement(node, localName);
	if (!el) return null;
	if (el.textContent) return el.textContent;
	if (el.children.length > 0) {
		return (
			el.children
				.map((c) => c.textContent)
				.join("")
				.trim() || null
		);
	}
	return null;
}

/** Reads a SAML attribute value by Name from an AttributeStatement. */
export function getSamlAttributeValue(assertion: XmlNode, attributeName: string): string | null {
	const attrStatement = findElement(assertion, "AttributeStatement");
	if (!attrStatement) return null;

	for (const attr of findAllElements(attrStatement, "Attribute")) {
		const name = attr.attributes.get("Name");
		if (name === attributeName) {
			const valueNode = findElement(attr, "AttributeValue");
			if (valueNode) return valueNode.textContent || null;
		}
	}
	return null;
}

/** Direct child elements with the given namespace and local name. */
export function childElements(node: XmlNode, ns: string, localName: string): XmlNode[] {
	return node.children.filter((c) => c.namespaceURI === ns && c.localName === localName);
}

/**
 * Text of a leaf element for use as a claim. Rejects child elements, comments and processing instructions,
 * so a value can never be split or truncated by markup the signature does not cover.
 */
export function strictText(node: XmlNode): string {
	let out = "";
	for (const c of node.content) {
		if (c.kind !== "text") {
			throw new SsoError(
				SSO_ERROR.SAML_INVALID_STRUCTURE,
				`<${node.localName}> must contain only text (found ${c.kind})`,
			);
		}
		out += c.value;
	}
	return out.trim();
}
