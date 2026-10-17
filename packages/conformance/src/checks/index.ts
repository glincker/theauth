import { authorizeChecks } from "./authorize.js";
import type { Check } from "./helpers.js";
import { metadataChecks } from "./metadata.js";
import { registrationChecks } from "./registration.js";
import { resourceChecks } from "./resource.js";
import { tokenChecks } from "./token.js";

export type { Check } from "./helpers.js";

export const ALL_CHECKS: Check[] = [
	...metadataChecks,
	...authorizeChecks,
	...registrationChecks,
	...tokenChecks,
	...resourceChecks,
];
