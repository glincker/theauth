import type { AuditExportOptions, AuditFilter, AuditPage } from "../types.js";
import type { createAuditModule } from "./audit.js";

type AuditModule = ReturnType<typeof createAuditModule>;

/** Public `theauth.audit` surface over the audit module. */
export function createAuditFacade(auditModule: AuditModule) {
	return {
		query: (filter: AuditFilter) => auditModule.query(filter),
		page: (filter: AuditFilter): Promise<AuditPage> => auditModule.page(filter),
		export: (options: AuditExportOptions) => auditModule.export(options),
		cleanup: (options: { retentionDays: number }) => auditModule.cleanup(options),
		replayAgent: (agentId: string, opts?: Parameters<AuditModule["replayAgent"]>[1]) =>
			auditModule.replayAgent(agentId, opts),
	};
}
