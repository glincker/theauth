/**
 * Template 07, Business-hours-only access
 *
 * The agent may execute a tool only between 09:00 and 17:00 in the server's
 * local time. Outside that window the engine returns allowed=false with a
 * reason string naming the window boundaries.
 *
 * Timezone caveat:
 * The engine uses new Date() and getHours()/getMinutes() on the server
 * process clock. There is no timezone conversion. Deploy in the correct
 * timezone (e.g. TZ=America/New_York) or run the process behind a proxy that
 * adjusts timestamps before calling evaluate(). See the README for details.
 *
 * Note: decisions involving timeWindow are never cached because the result
 * flips at window boundaries.
 */

import type { Permission } from "../../../../packages/core/src/types.js";

export const BUSINESS_HOURS_START = "09:00";
export const BUSINESS_HOURS_END = "17:00";

export const businessHoursPermissions: Permission[] = [
	{
		resource: "tool:send_email",
		actions: ["execute"],
		constraints: {
			timeWindow: {
				start: BUSINESS_HOURS_START,
				end: BUSINESS_HOURS_END,
			},
		},
	},
];
