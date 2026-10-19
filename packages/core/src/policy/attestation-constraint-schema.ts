import { z } from "zod";

/** Wire shape of `PermissionConstraints.attestation`. Strict so a misspelled field is an error, not a silently dropped rule. */
export const AttestationConstraintSchema = z
	.object({
		minSecurityLevel: z
			.enum(["hardware", "strongbox"])
			.optional()
			.describe("hardware accepts hardware and strongbox, strongbox accepts only strongbox"),
		bootState: z
			.array(z.enum(["verified", "self_signed", "unverified", "failed", "unlocked"]))
			.optional()
			.describe("The device boot state must be one of these (Android Key Attestation only)"),
		appIds: z
			.array(z.string().min(1))
			.optional()
			.describe(
				"One of the attested app ids (Android package, Apple teamId.bundleId) must be listed",
			),
	})
	.strict();
