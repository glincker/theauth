import { ddsTopicsForRules } from "./dds-topics.js";
import type { RosKind, RosVerb } from "./names.js";
import { verbsOf } from "./names.js";
import type { RosRule } from "./policy-model.js";

// Writers for the three XML files the ROS 2 security stack reads.
//   permissions.xml  DDS Security 1.1 section 9.4.1.3 (OMG formal/18-04-01), schema
//                    omg_shared_ca_permissions.xsd
//   governance.xml   DDS Security 1.1 section 9.4.1.2, schema omg_shared_ca_governance.xsd
//   policy.xml       SROS2 policy 0.2.0, the input of `ros2 security create_permission`
// All three are unsigned. Signing is a separate step done with the permissions CA key, which this
// library never sees.

export function escapeXml(value: string): string {
	return value
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;");
}

const XML_DECL = '<?xml version="1.0" encoding="UTF-8"?>';
const XSI = 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"';
const SCHEMA_BASE = "http://www.omg.org/spec/DDS-SECURITY/20170901";

/** An enclave path as `ros2 security` writes it: absolute, tokens of letters, digits, `_`, `-`, `.`. */
export function isValidEnclavePath(path: string): boolean {
	if (!/^\/(?:[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*)?$/.test(path)) return false;
	return !path.split("/").some((part) => part === "." || part === "..");
}

function assertEnclave(path: string): void {
	if (!isValidEnclavePath(path)) {
		throw new Error(`Invalid enclave path "${path}": use an absolute path like /fleet/robot1/nav`);
	}
}

function toDateTime(value: Date | string, label: string): string {
	const date = value instanceof Date ? value : new Date(value);
	if (Number.isNaN(date.getTime())) throw new Error(`Invalid ${label}: ${String(value)}`);
	return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

export interface PermissionsXmlOptions {
	/** Enclave path, for example `/fleet/robot1/nav`. Names the grant. */
	enclave: string;
	/**
	 * X.509 subject of the enclave certificate. DDS Security 1.1 requires an exact match, otherwise the
	 * grant is ignored. Default `CN=<enclave>`, which is what `ros2 security create_enclave` issues.
	 */
	subjectName?: string;
	/** DDS domain id, default 0 (the ROS_DOMAIN_ID default). */
	domainId?: number;
	/** Grant validity. Align it with the enclave certificate. Required: no clock is read here. */
	notBefore: Date | string;
	notAfter: Date | string;
	/** Add `ros_discovery_info` to publish and subscribe. Needed by Fast DDS, Cyclone DDS and Connext. Default true. */
	rosDiscoveryTopic?: boolean;
}

function topicsBlock(tag: "publish" | "subscribe", topics: string[]): string[] {
	if (topics.length === 0) return [];
	return [
		`        <${tag}>`,
		"          <topics>",
		...topics.map((t) => `            <topic>${escapeXml(t)}</topic>`),
		"          </topics>",
		`        </${tag}>`,
	];
}

function checkDomain(domainId: number): number {
	if (!Number.isInteger(domainId) || domainId < 0 || domainId > 232) {
		throw new Error(`Invalid DDS domain id ${domainId}: use an integer from 0 to 232`);
	}
	return domainId;
}

/** permissions.xml for one enclave. Rules end in `<default>DENY</default>`, so anything not listed is refused. */
export function renderPermissionsXml(
	rules: readonly RosRule[],
	options: PermissionsXmlOptions,
): string {
	assertEnclave(options.enclave);
	const domainId = checkDomain(options.domainId ?? 0);
	const subject = options.subjectName ?? `CN=${options.enclave}`;
	const topics = ddsTopicsForRules(rules, { rosDiscoveryTopic: options.rosDiscoveryTopic ?? true });
	const lines = [
		XML_DECL,
		`<dds ${XSI} xsi:noNamespaceSchemaLocation="${SCHEMA_BASE}/omg_shared_ca_permissions.xsd">`,
		"  <permissions>",
		`    <grant name="${escapeXml(options.enclave)}">`,
		`      <subject_name>${escapeXml(subject)}</subject_name>`,
		"      <validity>",
		`        <not_before>${toDateTime(options.notBefore, "notBefore")}</not_before>`,
		`        <not_after>${toDateTime(options.notAfter, "notAfter")}</not_after>`,
		"      </validity>",
		"      <allow_rule>",
		`        <domains><id>${domainId}</id></domains>`,
		...topicsBlock("publish", topics.publish),
		...topicsBlock("subscribe", topics.subscribe),
		"      </allow_rule>",
		"      <default>DENY</default>",
		"    </grant>",
		"  </permissions>",
		"</dds>",
		"",
	];
	return lines.join("\n");
}

export type ProtectionLevel = "encrypt" | "sign";

export interface GovernanceXmlOptions {
	domainId?: number;
	/**
	 * `encrypt` (default) matches the SROS2 default governance: encrypted discovery, liveliness and
	 * data, signed RTPS. `sign` keeps integrity and authentication but drops confidentiality.
	 */
	protection?: ProtectionLevel;
}

/** governance.xml for a domain. Unauthenticated participants are refused and join access control is on. */
export function renderGovernanceXml(options: GovernanceXmlOptions = {}): string {
	const domainId = checkDomain(options.domainId ?? 0);
	const kind = (options.protection ?? "encrypt") === "encrypt" ? "ENCRYPT" : "SIGN";
	return [
		XML_DECL,
		`<dds ${XSI} xsi:noNamespaceSchemaLocation="${SCHEMA_BASE}/omg_shared_ca_governance.xsd">`,
		"  <domain_access_rules>",
		"    <domain_rule>",
		`      <domains><id>${domainId}</id></domains>`,
		"      <allow_unauthenticated_participants>false</allow_unauthenticated_participants>",
		"      <enable_join_access_control>true</enable_join_access_control>",
		`      <discovery_protection_kind>${kind}</discovery_protection_kind>`,
		`      <liveliness_protection_kind>${kind}</liveliness_protection_kind>`,
		"      <rtps_protection_kind>SIGN</rtps_protection_kind>",
		"      <topic_access_rules>",
		"        <topic_rule>",
		"          <topic_expression>*</topic_expression>",
		"          <enable_discovery_protection>true</enable_discovery_protection>",
		"          <enable_liveliness_protection>true</enable_liveliness_protection>",
		"          <enable_read_access_control>true</enable_read_access_control>",
		"          <enable_write_access_control>true</enable_write_access_control>",
		`          <metadata_protection_kind>${kind}</metadata_protection_kind>`,
		`          <data_protection_kind>${kind}</data_protection_kind>`,
		"        </topic_rule>",
		"      </topic_access_rules>",
		"    </domain_rule>",
		"  </domain_access_rules>",
		"</dds>",
		"",
	].join("\n");
}

export interface Sros2PolicyOptions {
	enclave: string;
	/** Node name in the profile. Default: last token of the enclave path, or `robot` for `/`. */
	node?: string;
}

const LIST_TAG: Record<RosKind, { list: string; item: string }> = {
	topic: { list: "topics", item: "topic" },
	service: { list: "services", item: "service" },
	action: { list: "actions", item: "action" },
};

/** policy.xml in SROS2 policy format 0.2.0. Feed it to `ros2 security create_permission`. */
export function renderSros2PolicyXml(
	rules: readonly RosRule[],
	options: Sros2PolicyOptions,
): string {
	assertEnclave(options.enclave);
	const last = options.enclave.split("/").filter(Boolean).pop();
	const node = options.node ?? last ?? "robot";
	if (!/^[A-Za-z0-9_.-]+$/.test(node)) throw new Error(`Invalid node name "${node}"`);

	// One list element per kind and verb set, e.g. <topics publish="ALLOW" subscribe="ALLOW">.
	const groups = new Map<string, { kind: RosKind; verbs: RosVerb[]; names: string[] }>();
	for (const rule of rules) {
		const verbs = [...rule.verbs].sort();
		const key = `${rule.kind}:${verbs.join(",")}`;
		const group = groups.get(key) ?? { kind: rule.kind, verbs, names: [] };
		group.names.push(rule.name);
		groups.set(key, group);
	}
	const body: string[] = [];
	for (const group of [...groups.values()].sort((a, b) =>
		`${a.kind}${a.verbs}`.localeCompare(`${b.kind}${b.verbs}`),
	)) {
		const known = verbsOf(group.kind);
		const attrs = group.verbs
			.filter((v) => known.includes(v))
			.map((v) => `${v}="ALLOW"`)
			.join(" ");
		const tag = LIST_TAG[group.kind];
		body.push(`          <${tag.list} ${attrs}>`);
		for (const name of group.names.sort()) {
			body.push(`            <${tag.item}>${escapeXml(name)}</${tag.item}>`);
		}
		body.push(`          </${tag.list}>`);
	}
	return [
		XML_DECL,
		'<policy version="0.2.0">',
		"  <enclaves>",
		`    <enclave path="${escapeXml(options.enclave)}">`,
		"      <profiles>",
		`        <profile ns="/" node="${escapeXml(node)}">`,
		...body,
		"        </profile>",
		"      </profiles>",
		"    </enclave>",
		"  </enclaves>",
		"</policy>",
		"",
	].join("\n");
}
