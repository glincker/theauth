// Resource naming for ROS 2 graph objects inside theAuth permissions.
//
//   ros2:/cmd_vel              a topic          (actions: publish, subscribe)
//   ros2:srv:/reset            a service        (actions: call, reply)
//   ros2:action:/navigate      an action server (actions: call, execute)
//   ros2:* or *                every topic, service and action
//   ros2:srv:* ros2:action:*   every service, every action
//
// With the default matching, theAuth's policy engine (policy/abac.ts matchResource) treats `*` as a wildcard
// only when it is a whole colon separated segment. A glob inside a name such as `ros2:/fleet/*` would never
// match at runtime, so this module refuses it instead of exporting a DDS grant the runtime check would not
// agree with. With `resourceMatching: "path"` (policy/resource-match.ts) whole segment `*` and `**` inside a
// name are allowed, see parseRosResource. Names follow the ROS 2 topic and service name rules: absolute,
// `/` separated tokens of letters, digits and underscores
// (https://design.ros2.org/articles/topic_and_service_names.html).

export type RosKind = "topic" | "service" | "action";

/** The verbs SROS2 policy files use. Services use request and reply, actions use call and execute. */
export type RosVerb = "publish" | "subscribe" | "request" | "reply" | "call" | "execute";

export const ROS_KINDS: readonly RosKind[] = ["topic", "service", "action"];

const NAME_PATTERN = /^\/(?:[A-Za-z0-9_]+(?:\/[A-Za-z0-9_]+)*)?$/;

/** True for an absolute, fully qualified ROS 2 name other than the bare root. */
export function isValidRosName(name: string): boolean {
	return name !== "/" && NAME_PATTERN.test(name);
}

export function ros2Topic(name: string): string {
	return `ros2:${name}`;
}

export function ros2Service(name: string): string {
	return `ros2:srv:${name}`;
}

export function ros2Action(name: string): string {
	return `ros2:action:${name}`;
}

export type ParsedRosResource =
	| {
			ok: true;
			kinds: RosKind[];
			name: string | null;
			/** Path mode only: the name has a one level `*` segment (a DDS glob cannot express "exactly one level"). */
			singleLevel?: true;
	  }
	| { ok: false; reason: string };

/** `name` is null for a whole kind wildcard (every name of that kind). */
export function parseRosResource(
	resource: string,
	matching: "colon" | "path" = "colon",
): ParsedRosResource {
	if (resource === "*" || resource === "ros2:*") {
		return { ok: true, kinds: [...ROS_KINDS], name: null };
	}
	if (!resource.startsWith("ros2:")) {
		return { ok: false, reason: "not a ros2 resource" };
	}
	const rest = resource.slice("ros2:".length);
	let kind: RosKind = "topic";
	let name = rest;
	if (rest.startsWith("srv:")) {
		kind = "service";
		name = rest.slice("srv:".length);
	} else if (rest.startsWith("action:")) {
		kind = "action";
		name = rest.slice("action:".length);
	}
	if (name === "*") return { ok: true, kinds: [kind], name: null };
	if (matching === "path" && name.includes("*")) {
		const tokens = name.split("/");
		const valid =
			name.startsWith("/") &&
			tokens.slice(1).every((t) => t === "*" || t === "**" || /^[A-Za-z0-9_]+$/.test(t));
		if (!valid) {
			return {
				ok: false,
				reason: `"${name}" is not an absolute ROS 2 name (only whole segment * and ** are wildcards)`,
			};
		}
		return {
			ok: true,
			kinds: [kind],
			name,
			...(tokens.includes("*") && { singleLevel: true as const }),
		};
	}
	if (name.includes("*")) {
		return {
			ok: false,
			reason:
				"a glob inside a name never matches at runtime (the engine only honors a whole `*` segment), list exact names",
		};
	}
	if (!isValidRosName(name)) {
		return { ok: false, reason: `"${name}" is not an absolute ROS 2 name` };
	}
	return { ok: true, kinds: [kind], name };
}

const VERBS: Record<RosKind, readonly RosVerb[]> = {
	topic: ["publish", "subscribe"],
	service: ["request", "reply"],
	action: ["call", "execute"],
};

export function verbsOf(kind: RosKind): readonly RosVerb[] {
	return VERBS[kind];
}

/**
 * Map a theAuth action to a verb for one kind. `*` means every verb of the kind. For services,
 * `call` is accepted as an alias of `request` so one action word works for services and actions.
 */
export function verbsForAction(kind: RosKind, action: string): RosVerb[] {
	if (action === "*") return [...VERBS[kind]];
	if (kind === "service" && action === "call") return ["request"];
	return VERBS[kind].includes(action as RosVerb) ? [action as RosVerb] : [];
}
