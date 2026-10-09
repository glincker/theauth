import type { ImportSource, SourceParser } from "../types.js";
import { auth0Parser } from "./auth0.js";
import { clerkParser } from "./clerk.js";
import { genericParser } from "./generic.js";
import { keycloakParser } from "./keycloak.js";
import { betterAuthParser, nextAuthParser } from "./tables.js";

const PARSERS: Record<ImportSource, SourceParser> = {
	auth0: auth0Parser,
	keycloak: keycloakParser,
	clerk: clerkParser,
	"better-auth": betterAuthParser,
	nextauth: nextAuthParser,
	generic: genericParser,
};

export function getParser(source: ImportSource): SourceParser {
	return PARSERS[source];
}
