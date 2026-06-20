import type { DynamicModule, MiddlewareConsumer, NestModule } from "@nestjs/common";
import { Inject, Module } from "@nestjs/common";
import type { Kavach } from "theauth";
import type { McpAuthModule } from "theauth/mcp";
import { kavachMiddleware } from "./adapter.js";

// ─── Injection Token ──────────────────────────────────────────────────────────

const KAVACH_OPTIONS = Symbol("KAVACH_OPTIONS");

// ─── Module Options ───────────────────────────────────────────────────────────

export interface KavachModuleOptions {
	/** The Kavach instance created with `createKavach()` */
	kavach: Kavach;
	/** Optional MCP OAuth 2.1 module created with `createMcpModule()` */
	mcp?: McpAuthModule;
	/**
	 * The path prefix where TheAuth routes will be mounted.
	 * @default '/api/kavach'
	 */
	basePath?: string;
}

// ─── KavachModule ─────────────────────────────────────────────────────────────

/**
 * NestJS dynamic module that mounts all TheAuth REST routes as Express
 * middleware. Import it once in your root `AppModule`.
 *
 * @example
 * ```typescript
 * // app.module.ts
 * import { Module } from '@nestjs/common';
 * import { KavachModule } from '@theauth/nestjs';
 * import { kavach, mcp } from './lib/kavach.js';
 *
 * @Module({
 *   imports: [
 *     KavachModule.forRoot({ kavach, mcp, basePath: '/api/kavach' }),
 *   ],
 * })
 * export class AppModule {}
 * ```
 */
@Module({})
export class KavachModule implements NestModule {
	constructor(
		@Inject(KAVACH_OPTIONS)
		private readonly options: KavachModuleOptions,
	) {}

	configure(consumer: MiddlewareConsumer): void {
		const basePath = this.options.basePath ?? "/api/kavach";
		consumer
			.apply(
				kavachMiddleware({
					kavach: this.options.kavach,
					mcp: this.options.mcp,
				}),
			)
			.forRoutes(`${basePath}/*path`);
	}

	static forRoot(options: KavachModuleOptions): DynamicModule {
		return {
			module: KavachModule,
			providers: [
				{
					provide: KAVACH_OPTIONS,
					useValue: options,
				},
			],
		};
	}
}
