import type { Database } from "../db/database.js";
import type { AuditConfig } from "../types.js";
import { createAuditModule } from "./audit.js";
import { enableAuditChain } from "./chain.js";
import { setAuditWriteErrorHandler } from "./record.js";

/** Applies `config.audit` to the database (tamper evident chain, write error handler) and returns the audit module. */
export function createConfiguredAuditModule(db: Database, config: AuditConfig | undefined) {
	if (config?.tamperEvident)
		enableAuditChain(db, { hmacKey: config.hmacKey, pseudonymRotation: config.pseudonymRotation });
	setAuditWriteErrorHandler(db, config?.onAuditError);
	return createAuditModule({ db, hmacKey: config?.hmacKey });
}
