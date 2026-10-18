/**
 * Exclusive c14n differential tests. Expected bytes were produced once by `xmllint --exc-c14n` (whole documents)
 * and libxml2 through lxml (signature subsets) and committed under tests/fixtures/saml.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { excC14n, parsePrefixList } from "../src/auth/saml-c14n.js";
import { DSIG_NS, findSignatures } from "../src/auth/saml-signature.js";
import type { XmlNode } from "../src/auth/sso-types.js";
import { parseXml } from "../src/auth/sso-xml.js";

const DIR = join(__dirname, "fixtures", "saml");
const read = (f: string) => readFileSync(join(DIR, f), "utf8");
const EXC_NS = "http://www.w3.org/2001/10/xml-exc-c14n#";

const edgeCases = readdirSync(DIR)
	.filter((f) => f.startsWith("edge-") && f.endsWith(".xml") && !f.endsWith(".exc-c14n.xml"))
	.map((f) => f.slice(0, -4));
const signedFixtures = readdirSync(DIR)
	.filter((f) => f.endsWith(".subsets.json"))
	.map((f) => f.slice(0, -".subsets.json".length));

function child(node: XmlNode, localName: string): XmlNode {
	const found = node.children.find((c) => c.namespaceURI === DSIG_NS && c.localName === localName);
	if (!found) throw new Error(`missing ${localName}`);
	return found;
}

function prefixesOf(algNode: XmlNode): string[] {
	const inc = algNode.children.find((c) => c.namespaceURI === EXC_NS);
	return parsePrefixList(inc?.attributes.get("PrefixList"));
}

describe("exclusive c14n matches xmllint --exc-c14n on edge cases", () => {
	it("covers the expected edge cases", () => {
		expect(edgeCases).toEqual(
			expect.arrayContaining([
				"edge-ns-inheritance",
				"edge-default-ns",
				"edge-attr-sorting",
				"edge-whitespace",
				"edge-escaping",
				"edge-cdata",
				"edge-empty-elements",
				"edge-comments",
			]),
		);
	});

	for (const name of edgeCases) {
		it(`${name} (with comments, as xmllint emits)`, () => {
			const doc = parseXml(read(`${name}.xml`));
			expect(excC14n(doc, { withComments: true })).toBe(read(`${name}.exc-c14n.xml`));
		});
	}

	it("drops comments without the WithComments variant", () => {
		const doc = parseXml(read("edge-comments.xml"));
		expect(excC14n(doc)).toBe("<r><a>xy</a></r>");
	});

	it("renders an InclusiveNamespaces prefix even when not visibly used", () => {
		const doc = parseXml('<a:r xmlns:a="urn:a" xmlns:b="urn:b"><a:x/></a:r>');
		const inner = doc.children[0] as XmlNode;
		expect(excC14n(inner)).toBe('<a:x xmlns:a="urn:a"></a:x>');
		expect(excC14n(inner, { inclusivePrefixes: ["b"] })).toBe(
			'<a:x xmlns:a="urn:a" xmlns:b="urn:b"></a:x>',
		);
	});

	it('emits xmlns="" only when an output ancestor rendered a default namespace', () => {
		const doc = parseXml('<r xmlns="urn:d"><c xmlns=""><d/></c></r>');
		const c = doc.children[0] as XmlNode;
		expect(excC14n(c)).toBe("<c><d></d></c>");
		expect(excC14n(doc)).toBe('<r xmlns="urn:d"><c xmlns=""><d></d></c></r>');
	});
});

describe("exclusive c14n matches libxml2 on signed fixtures", () => {
	for (const name of signedFixtures) {
		it(`${name}: whole document`, () => {
			const doc = parseXml(read(`${name}.xml`));
			expect(excC14n(doc, { withComments: true })).toBe(read(`${name}.exc-c14n.xml`));
		});

		it(`${name}: SignedInfo and referenced element without its Signature`, () => {
			const doc = parseXml(read(`${name}.xml`));
			const expected = JSON.parse(read(`${name}.subsets.json`)) as Record<string, string>;
			const sigs = findSignatures(doc);
			expect(sigs.length).toBeGreaterThan(0);
			for (const { signature, parent } of sigs) {
				const signedInfo = child(signature, "SignedInfo");
				const cm = child(signedInfo, "CanonicalizationMethod");
				const withComments = cm.attributes.get("Algorithm")?.endsWith("WithComments") === true;
				expect(excC14n(signedInfo, { withComments, inclusivePrefixes: prefixesOf(cm) })).toBe(
					expected[`${parent.localName}.signedinfo`],
				);

				const transforms = child(child(signedInfo, "Reference"), "Transforms").children;
				const last = transforms[transforms.length - 1] as XmlNode;
				expect(excC14n(parent, { exclude: signature, inclusivePrefixes: prefixesOf(last) })).toBe(
					expected[`${parent.localName}.ref`],
				);
			}
		});
	}
});
