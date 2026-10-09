import { pbkdf2Hash } from "../crypto/web-crypto.js";
import type { ExternalIdentity, ExternalIssuers } from "./external-issuers.js";
import type { Rollout, System } from "./rollout.js";
import type { ImportedUser, MigrationStore } from "./types.js";

export interface OnboardingConfig {
	issuers: ExternalIssuers;
	store: MigrationStore;
	rollout: Rollout;
	/** Create the theauth account on first sight. Off by default. */
	jit?: boolean;
	/**
	 * Link to an existing theauth account with the same email. Only happens when the
	 * incumbent says the email is verified. Off by default.
	 */
	linkVerifiedEmail?: boolean;
	/** Replace default user creation, e.g. to create an agent identity. */
	provision?: (identity: ExternalIdentity) => Promise<{ id: string }>;
	/** Called after every attempt with no personal data. Errors are swallowed. */
	onOutcome?: (outcome: OnboardingOutcome) => void | Promise<void>;
}

export type OnboardingAction = "created" | "linked" | "existing" | "skipped" | "failed";

export interface OnboardingOutcome {
	/** Always "incumbent" unless the user was onboarded and the caller opted to serve from theauth. */
	servedBy: System;
	cohort: string;
	action: OnboardingAction;
	userId?: string;
	passwordMigrated: boolean;
	errorCode?: string;
}

export interface LoginInput {
	/** The token the incumbent just issued for this login. */
	token: string;
	/** Optional: the plaintext the user typed, so the hash can be migrated now. Never stored or logged. */
	password?: string;
}

/**
 * The login hook. Call it after the incumbent has authenticated the user. It never throws
 * and never fails the login: every problem becomes `action: "failed"` and the incumbent
 * keeps serving that user.
 */
export function createLoginOnboarding(config: OnboardingConfig) {
	const { issuers, store, rollout } = config;

	async function finish(o: OnboardingOutcome): Promise<OnboardingOutcome> {
		try {
			await config.onOutcome?.(o);
		} catch {
			// Reporting must not affect login.
		}
		return o;
	}

	async function record(
		status: "migrated" | "failed",
		source: string,
		userId: string | null,
		cohort: string,
		errorCode: string | null,
	): Promise<void> {
		try {
			await store.recordMigration({ userId, source, status, cohort, errorCode, at: new Date() });
		} catch {
			// Ledger trouble is not a login problem.
		}
	}

	async function onLogin(input: LoginInput): Promise<OnboardingOutcome> {
		const base = { servedBy: "incumbent" as System, passwordMigrated: false };
		const verified = await issuers.verify(input.token);
		if (!verified.success) {
			return finish({
				...base,
				cohort: "unknown",
				action: "failed",
				errorCode: verified.error.code,
			});
		}
		const id = verified.data;
		try {
			const assignment = await rollout.assignCohort({
				id: `${id.issuer}:${id.subject}`,
				...(id.email ? { email: id.email } : {}),
			});
			if (assignment.system === "incumbent") {
				return finish({ ...base, cohort: assignment.cohort, action: "skipped" });
			}
			const cohort = assignment.cohort;
			let action: OnboardingAction = "existing";
			let userId: string;
			const existing = await store.findBySourceId(id.issuer, id.subject);
			if (existing) {
				userId = existing.id;
			} else if (!config.jit) {
				return finish({ ...base, cohort, action: "skipped", errorCode: "JIT_DISABLED" });
			} else {
				const byEmail = id.email ? await store.findByEmail(id.email) : null;
				if (byEmail && !(config.linkVerifiedEmail && id.emailVerified)) {
					await record("failed", id.issuer, null, cohort, "EMAIL_CONFLICT");
					return finish({ ...base, cohort, action: "failed", errorCode: "EMAIL_CONFLICT" });
				}
				if (byEmail) {
					await store.updateUser(byEmail.id, toImported(id));
					userId = byEmail.id;
					action = "linked";
				} else if (config.provision) {
					userId = (await config.provision(id)).id;
					action = "created";
				} else if (id.email) {
					userId = (await store.createUser(toImported(id), id.issuer)).id;
					action = "created";
				} else {
					await record("failed", id.issuer, null, cohort, "NO_EMAIL");
					return finish({ ...base, cohort, action: "failed", errorCode: "NO_EMAIL" });
				}
			}

			let passwordMigrated = false;
			if (input.password) {
				try {
					if ((await store.getPasswordHash(userId)) === null) {
						await store.setPasswordHash(userId, await pbkdf2Hash(input.password));
						passwordMigrated = true;
					}
				} catch {
					passwordMigrated = false;
				}
			}
			await record("migrated", id.issuer, userId, cohort, null);
			return finish({ servedBy: "theauth", cohort, action, userId, passwordMigrated });
		} catch {
			await record("failed", id.issuer, null, "unknown", "ONBOARDING_ERROR");
			return finish({
				...base,
				cohort: "unknown",
				action: "failed",
				errorCode: "ONBOARDING_ERROR",
			});
		}
	}

	return { onLogin };
}

function toImported(id: ExternalIdentity): ImportedUser {
	return {
		externalId: id.subject,
		email: id.email ?? "",
		emailVerified: id.emailVerified,
		name: id.name,
		linkedAccounts: [],
		metadata: {},
	};
}
