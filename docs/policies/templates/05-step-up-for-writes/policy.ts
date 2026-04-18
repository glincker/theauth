/**
 * Template 05, Step-up approval for writes
 *
 * Read operations are permitted immediately. Write and delete operations
 * require human approval before execution. The engine enforces this by
 * returning allowed=false with reason "This action requires human approval
 * before execution" whenever requireApproval=true is evaluated.
 *
 * Your application should intercept that denial and open an approval flow
 * (e.g. send a Slack message, insert into kavach_approval_requests) before
 * retrying the evaluate call after the human approves.
 */

import type { Permission } from "../../../../packages/core/src/types.js";

export const stepUpPermissions: Permission[] = [
	{
		resource: "database:records",
		actions: ["read"],
	},
	{
		resource: "database:records",
		actions: ["write", "delete"],
		constraints: {
			requireApproval: true,
		},
	},
];
