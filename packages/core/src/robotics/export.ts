import type { NodeBaselineOptions } from "./node-baseline.js";
import { isValidNodeBaseline, nodeBaselinePermissions } from "./node-baseline.js";
import type { BuildRosPolicyOptions, RoboticsPermission, RosPolicy } from "./policy-model.js";
import { buildRosPolicy } from "./policy-model.js";
import type { GovernanceXmlOptions, PermissionsXmlOptions } from "./xml.js";
import { renderGovernanceXml, renderPermissionsXml, renderSros2PolicyXml } from "./xml.js";

export interface Ros2ExportOptions extends BuildRosPolicyOptions {
	robotId?: string;
	enclave: string;
	subjectName?: string;
	domainId?: number;
	notBefore: Date | string;
	notAfter: Date | string;
	rosDiscoveryTopic?: boolean;
	protection?: GovernanceXmlOptions["protection"];
	node?: string;
	/**
	 * Add what every ROS 2 node needs to start under Enforce (`/rosout`, `/parameter_events`, its
	 * parameter services). `true` uses the policy node name (`node`, or the last enclave token) in
	 * namespace "/". Off by default in the library, on by default in the CLI.
	 */
	nodeBaseline?: boolean | Partial<NodeBaselineOptions>;
}

export interface Ros2Export {
	/** File name to content. Always: policy.xml, permissions.xml, governance.xml, theauth-export.json. */
	files: Record<string, string>;
	policy: RosPolicy;
}

/** Everything `theauth ros2 export` writes, as strings. No file system access. */
export function exportRos2(
	permissions: readonly RoboticsPermission[],
	options: Ros2ExportOptions,
): Ros2Export {
	const baseline = resolveBaseline(options);
	const policy = buildRosPolicy([...permissions, ...baseline.permissions], {
		gated: options.gated,
		resourceMatching: options.resourceMatching,
		singleLevel: options.singleLevel,
	});
	const permissionsOptions: PermissionsXmlOptions = {
		enclave: options.enclave,
		subjectName: options.subjectName,
		domainId: options.domainId,
		notBefore: options.notBefore,
		notAfter: options.notAfter,
		rosDiscoveryTopic: options.rosDiscoveryTopic,
	};
	const report = {
		robotId: options.robotId ?? null,
		enclave: options.enclave,
		gatedMode: options.gated ?? "omit",
		resourceMatching: options.resourceMatching ?? "colon",
		nodeBaseline: baseline.report,
		rules: policy.rules,
		gated: policy.gated,
		skipped: policy.skipped,
	};
	return {
		policy,
		files: {
			"policy.xml": renderSros2PolicyXml(policy.rules, {
				enclave: options.enclave,
				node: options.node,
			}),
			"permissions.xml": renderPermissionsXml(policy.rules, permissionsOptions),
			"governance.xml": renderGovernanceXml({
				domainId: options.domainId,
				protection: options.protection,
			}),
			"theauth-export.json": `${JSON.stringify(report, null, 2)}\n`,
		},
	};
}

function resolveBaseline(options: Ros2ExportOptions): {
	permissions: RoboticsPermission[];
	report: string;
} {
	const opt = options.nodeBaseline;
	if (!opt) return { permissions: [], report: "off" };
	const explicit = typeof opt === "object" ? opt : {};
	const fromEnclave = options.enclave.split("/").filter(Boolean).pop() ?? "robot";
	const node = explicit.node ?? options.node ?? fromEnclave;
	const resolved: NodeBaselineOptions = { node, namespace: explicit.namespace };
	if (isValidNodeBaseline(resolved)) {
		return { permissions: nodeBaselinePermissions(resolved), report: `node ${node}` };
	}
	if (explicit.node !== undefined || options.node !== undefined) {
		// An explicit name that cannot be a ROS node name is a mistake, say so.
		return { permissions: nodeBaselinePermissions(resolved), report: "" };
	}
	return {
		permissions: [],
		report: `skipped: "${node}" is not a valid ROS node name, pass --node`,
	};
}
