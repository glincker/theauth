/** Namespace-aware XML parser and element helpers for SAML responses. */

import type { XmlNode } from "./sso-types.js";
import { SSO_ERROR, SsoError } from "./sso-types.js";

// Minimal XML parser (no regex for structure)

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

export function stripXmlComments(xml: string): string {
	let result = "";
	let i = 0;
	while (i < xml.length) {
		if (xml[i] === "<" && xml[i + 1] === "!" && xml[i + 2] === "-" && xml[i + 3] === "-") {
			const endIdx = xml.indexOf("-->", i + 4);
			if (endIdx === -1) {
				throw new SsoError(SSO_ERROR.SAML_XML_PARSE_ERROR, "Unterminated XML comment");
			}
			i = endIdx + 3;
		} else {
			result += xml[i];
			i++;
		}
	}
	return result;
}

function parseAttributes(attrString: string): Map<string, string> {
	const attrs = new Map<string, string>();
	let i = 0;
	const s = attrString.trim();

	while (i < s.length) {
		while (i < s.length && /\s/.test(s[i] as string)) i++;
		if (i >= s.length) break;

		let name = "";
		while (i < s.length && s[i] !== "=" && !/\s/.test(s[i] as string)) {
			name += s[i];
			i++;
		}
		if (!name) break;

		while (i < s.length && /\s/.test(s[i] as string)) i++;
		if (i >= s.length || s[i] !== "=") break;
		i++; // skip =
		while (i < s.length && /\s/.test(s[i] as string)) i++;

		const quote = s[i];
		if (quote !== '"' && quote !== "'") break;
		i++; // skip opening quote

		let value = "";
		while (i < s.length && s[i] !== quote) {
			if (s[i] === "&") {
				const entityEnd = s.indexOf(";", i);
				if (entityEnd === -1) break;
				const entity = s.substring(i, entityEnd + 1);
				switch (entity) {
					case "&amp;":
						value += "&";
						break;
					case "&lt;":
						value += "<";
						break;
					case "&gt;":
						value += ">";
						break;
					case "&apos;":
						value += "'";
						break;
					case "&quot;":
						value += '"';
						break;
					default:
						value += entity;
						break;
				}
				i = entityEnd + 1;
			} else {
				value += s[i];
				i++;
			}
		}
		i++; // skip closing quote

		attrs.set(name, value);
	}

	return attrs;
}

function splitTagName(tagName: string): { prefix: string; localName: string } {
	const colonIdx = tagName.indexOf(":");
	if (colonIdx === -1) return { prefix: "", localName: tagName };
	return { prefix: tagName.substring(0, colonIdx), localName: tagName.substring(colonIdx + 1) };
}

/** Parses XML into an XmlNode tree. Covers only the subset found in SAML responses. */
export function parseXml(xml: string): XmlNode {
	checkXxe(xml);
	const cleaned = stripXmlComments(xml).trim();

	const rootResult = parseElement(cleaned, 0);
	if (!rootResult) {
		throw new SsoError(
			SSO_ERROR.SAML_XML_PARSE_ERROR,
			"Failed to parse XML: no root element found",
		);
	}
	return rootResult.node;
}

interface ParseResult {
	node: XmlNode;
	endIndex: number;
}

function parseElement(xml: string, startIdx: number): ParseResult | null {
	let i = startIdx;

	while (i < xml.length) {
		while (i < xml.length && /\s/.test(xml[i] as string)) i++;
		if (i >= xml.length) return null;

		if (xml[i] === "<" && xml[i + 1] === "?") {
			const piEnd = xml.indexOf("?>", i + 2);
			if (piEnd === -1) return null;
			i = piEnd + 2;
			continue;
		}
		break;
	}

	if (i >= xml.length || xml[i] !== "<") return null;
	i++; // skip <

	let tagName = "";
	while (i < xml.length && xml[i] !== ">" && xml[i] !== "/" && !/\s/.test(xml[i] as string)) {
		tagName += xml[i];
		i++;
	}

	if (!tagName) return null;

	let attrString = "";
	while (i < xml.length && xml[i] !== ">" && !(xml[i] === "/" && xml[i + 1] === ">")) {
		attrString += xml[i];
		i++;
	}

	const attributes = parseAttributes(attrString);
	const { prefix, localName } = splitTagName(tagName);

	if (xml[i] === "/" && xml[i + 1] === ">") {
		const outerXml = xml.substring(startIdx, i + 2);
		return {
			node: {
				localName,
				prefix,
				tagName,
				attributes,
				children: [],
				textContent: "",
				rawInnerXml: "",
				rawOuterXml: outerXml,
			},
			endIndex: i + 2,
		};
	}

	if (xml[i] !== ">") return null;
	i++; // skip >

	const contentStart = i;

	const children: XmlNode[] = [];
	let textContent = "";

	while (i < xml.length) {
		if (xml[i] === "<") {
			if (xml.substring(i, i + 9) === "<![CDATA[") {
				const cdataEnd = xml.indexOf("]]>", i + 9);
				if (cdataEnd === -1) {
					throw new SsoError(SSO_ERROR.SAML_XML_PARSE_ERROR, "Unterminated CDATA section");
				}
				textContent += xml.substring(i + 9, cdataEnd);
				i = cdataEnd + 3;
				continue;
			}

			if (xml[i + 1] === "/") {
				const closeTagStart = i + 2;
				let closeTagName = "";
				let ci = closeTagStart;
				while (ci < xml.length && xml[ci] !== ">" && !/\s/.test(xml[ci] as string)) {
					closeTagName += xml[ci];
					ci++;
				}
				while (ci < xml.length && xml[ci] !== ">") ci++;

				if (closeTagName === tagName) {
					const rawInnerXml = xml.substring(contentStart, i);
					const rawOuterXml = xml.substring(startIdx, ci + 1);
					return {
						node: {
							localName,
							prefix,
							tagName,
							attributes,
							children,
							textContent: textContent.trim(),
							rawInnerXml,
							rawOuterXml,
						},
						endIndex: ci + 1,
					};
				}
				throw new SsoError(
					SSO_ERROR.SAML_XML_PARSE_ERROR,
					`Mismatched closing tag: expected </${tagName}> but found </${closeTagName}>`,
				);
			}

			const childResult = parseElement(xml, i);
			if (childResult) {
				children.push(childResult.node);
				i = childResult.endIndex;
			} else {
				i++;
			}
		} else {
			let ch = xml[i] as string;
			if (ch === "&") {
				const entityEnd = xml.indexOf(";", i);
				if (entityEnd !== -1) {
					const entity = xml.substring(i, entityEnd + 1);
					switch (entity) {
						case "&amp;":
							ch = "&";
							break;
						case "&lt;":
							ch = "<";
							break;
						case "&gt;":
							ch = ">";
							break;
						case "&apos;":
							ch = "'";
							break;
						case "&quot;":
							ch = '"';
							break;
						default:
							ch = entity;
							break;
					}
					i = entityEnd + 1;
				} else {
					i++;
				}
			} else {
				i++;
			}
			textContent += ch;
		}
	}

	throw new SsoError(SSO_ERROR.SAML_XML_PARSE_ERROR, `Unterminated element: <${tagName}>`);
}

/** Finds the first descendant with a matching local name (namespace-agnostic). */
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
