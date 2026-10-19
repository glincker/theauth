import { ros2Service, ros2Topic } from "./names.js";
import type { RoboticsPermission } from "./policy-model.js";

/**
 * Every ROS 2 node (rclcpp and rclpy alike) opens a few DDS endpoints before user code runs. Under
 * `ROS_SECURITY_STRATEGY=Enforce` a participant that lacks them fails at node creation. Observed on
 * ros:humble with rmw_fastrtps_cpp: first `rt/rosout`, then the parameter services, then (when the
 * node is created with default options) `rt/parameter_events`. SROS2's `create_permission` does not
 * add them, so a policy that lists only the application topics produces an enclave that cannot start.
 */
export const PARAMETER_SERVICES = [
	"describe_parameters",
	"get_parameter_types",
	"get_parameters",
	"list_parameters",
	"set_parameters",
	"set_parameters_atomically",
] as const;

export interface NodeBaselineOptions {
	/** The ROS node name (not the enclave). Letters, digits and underscores. */
	node: string;
	/** The node's namespace. Default "/". */
	namespace?: string;
}

const NODE_NAME = /^[A-Za-z0-9_]+$/;
const NAMESPACE = /^\/(?:[A-Za-z0-9_]+(?:\/[A-Za-z0-9_]+)*)?$/;

export function isValidNodeBaseline(options: NodeBaselineOptions): boolean {
	return NODE_NAME.test(options.node) && NAMESPACE.test(options.namespace ?? "/");
}

/** The permissions a plain node needs to start: logging, parameter events and its own parameter services. */
export function nodeBaselinePermissions(options: NodeBaselineOptions): RoboticsPermission[] {
	if (!isValidNodeBaseline(options)) {
		throw new Error(
			`Invalid node baseline: node "${options.node}" must be letters, digits and underscores and the namespace an absolute ROS name`,
		);
	}
	const ns = options.namespace ?? "/";
	const prefix = `${ns === "/" ? "" : ns}/${options.node}`;
	return [
		{ resource: ros2Topic("/rosout"), actions: ["publish"] },
		{ resource: ros2Topic("/parameter_events"), actions: ["publish", "subscribe"] },
		...PARAMETER_SERVICES.map((s) => ({
			resource: ros2Service(`${prefix}/${s}`),
			actions: ["reply"],
		})),
	];
}
