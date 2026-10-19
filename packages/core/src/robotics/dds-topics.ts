import type { RosRule } from "./policy-model.js";

// ROS 2 maps graph objects to DDS topic names with a prefix and suffix (design.ros2.org,
// "ROS 2 on DDS" and the SROS2 permissions.xsl template):
//   topic            rt/<name>
//   service request  rq/<name>Request
//   service reply    rr/<name>Reply
//   action           a service trio (send_goal, cancel_goal, get_result) plus rt feedback and status
//                    under <name>/_action/

export interface DdsTopics {
	publish: string[];
	subscribe: string[];
}

const ACTION_SERVICES = ["cancel_goal", "get_result", "send_goal"] as const;
const ACTION_TOPICS = ["feedback", "status"] as const;

function actionRequests(name: string): string[] {
	return ACTION_SERVICES.map((s) => `rq${name}/_action/${s}Request`);
}

function actionReplies(name: string): string[] {
	return ACTION_SERVICES.map((s) => `rr${name}/_action/${s}Reply`);
}

function actionStreams(name: string): string[] {
	return ACTION_TOPICS.map((t) => `rt${name}/_action/${t}`);
}

/** DDS topic names one rule needs to publish and to subscribe to. */
export function ddsTopicsForRule(rule: RosRule): DdsTopics {
	const publish: string[] = [];
	const subscribe: string[] = [];
	const { name } = rule;
	for (const verb of rule.verbs) {
		switch (verb) {
			case "publish":
				publish.push(`rt${name}`);
				break;
			case "subscribe":
				subscribe.push(`rt${name}`);
				break;
			case "request":
				publish.push(`rq${name}Request`);
				subscribe.push(`rr${name}Reply`);
				break;
			case "reply":
				publish.push(`rr${name}Reply`);
				subscribe.push(`rq${name}Request`);
				break;
			case "call":
				publish.push(...actionRequests(name));
				subscribe.push(...actionReplies(name), ...actionStreams(name));
				break;
			case "execute":
				publish.push(...actionReplies(name), ...actionStreams(name));
				subscribe.push(...actionRequests(name));
				break;
		}
	}
	return { publish, subscribe };
}

/** Sorted, de-duplicated topic lists for a whole policy. */
export function ddsTopicsForRules(
	rules: readonly RosRule[],
	options: { rosDiscoveryTopic?: boolean } = {},
): DdsTopics {
	const publish = new Set<string>();
	const subscribe = new Set<string>();
	for (const rule of rules) {
		const topics = ddsTopicsForRule(rule);
		for (const t of topics.publish) publish.add(t);
		for (const t of topics.subscribe) subscribe.add(t);
	}
	if (options.rosDiscoveryTopic) {
		publish.add("ros_discovery_info");
		subscribe.add("ros_discovery_info");
	}
	return { publish: [...publish].sort(), subscribe: [...subscribe].sort() };
}
