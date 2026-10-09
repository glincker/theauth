import type { Result } from "../mcp/types.js";

export type { Result };

export type ImportSource = "auth0" | "keycloak" | "clerk" | "better-auth" | "nextauth" | "generic";

export const IMPORT_SOURCES: readonly ImportSource[] = [
	"auth0",
	"keycloak",
	"clerk",
	"better-auth",
	"nextauth",
	"generic",
];

export type LegacyAlgorithm =
	| "bcrypt"
	| "argon2"
	| "scrypt"
	| "pbkdf2-sha1"
	| "pbkdf2-sha256"
	| "pbkdf2-sha512"
	| "pbkdf2-theauth";

/** A hash exactly as the old system stored it, plus what is needed to check it. */
export interface LegacyHash {
	algorithm: LegacyAlgorithm;
	/** bcrypt and argon2: the full encoded string. Others: base64 of the derived key. */
	hash: string;
	/** Base64 salt for scrypt and pbkdf2 variants. */
	salt?: string;
	/** Iterations (pbkdf2), or N, r, p (scrypt). */
	params?: { iterations?: number; N?: number; r?: number; p?: number; nfkc?: boolean };
}

export interface LinkedAccount {
	provider: string;
	providerAccountId: string;
}

export interface ImportedUser {
	externalId: string;
	email: string;
	emailVerified: boolean;
	name: string | null;
	passwordHash?: LegacyHash;
	linkedAccounts: LinkedAccount[];
	metadata: Record<string, unknown>;
}

/** One source record that could not be turned into a user. Never carries field values. */
export interface ParseIssue {
	row: number;
	code: string;
	message: string;
}

export interface ParseOutput {
	users: ImportedUser[];
	issues: ParseIssue[];
}

/** Everything a source needs: raw text, or for DB sources a JSON document of tables. */
export interface SourceParser {
	source: ImportSource;
	parse(text: string, options?: ParseOptions): ParseOutput;
}

export interface ParseOptions {
	mapping?: GenericMapping;
	/** Auth0 only: the separate password hash export (newline-delimited JSON). */
	passwordHashes?: string;
}

/** Column or field names for the generic importer. */
export interface GenericMapping {
	externalId?: string;
	email?: string;
	emailVerified?: string;
	name?: string;
	passwordHash?: string;
}

export type ConflictPolicy = "skip" | "update" | "fail";

export interface StoredUser {
	id: string;
	email: string;
	externalId: string | null;
	source: string | null;
}

export type MigrationStatus = "migrated" | "pending" | "failed";

/** What the ledger keeps. Deliberately has no email, name or hash. */
export interface MigrationRecord {
	userId: string | null;
	source: string;
	status: MigrationStatus;
	cohort: string | null;
	errorCode: string | null;
	at: Date;
}

/** The narrow persistence surface the toolkit needs. Bring your own or use the bundled ones. */
export interface MigrationStore {
	findBySourceId(source: string, externalId: string): Promise<StoredUser | null>;
	findByEmail(email: string): Promise<StoredUser | null>;
	createUser(user: ImportedUser, source: string): Promise<StoredUser>;
	updateUser(id: string, user: ImportedUser): Promise<void>;
	getPasswordHash(userId: string): Promise<string | null>;
	setPasswordHash(userId: string, encoded: string): Promise<void>;
	recordMigration(record: MigrationRecord): Promise<void>;
	listMigrations(): Promise<MigrationRecord[]>;
}

export function ok<T>(data: T): Result<T> {
	return { success: true, data };
}

export function err(code: string, message: string): Result<never> {
	return { success: false, error: { code, message } };
}
