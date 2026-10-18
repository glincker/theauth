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
	const policy = buildRosPolicy(permissions, {
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
