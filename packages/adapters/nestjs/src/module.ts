import type { Kavach } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import type { DynamicModule, MiddlewareConsumer, NestModule } from "@nestjs/common";
import { Inject, Module } from "@nestjs/common";
import { authMiddleware } from "./adapter.js";

// ─── Injection Token ──────────────────────────────────────────────────────────

const AUTH_OPTIONS = Symbol("AUTH_OPTIONS");

// ─── Module Options ───────────────────────────────────────────────────────────

export interface AuthModuleOptions {
	/** The Auth instance created with `createAuth()` */
	kavach: Kavach;
	/** Optional MCP OAuth 2.1 module created with `createMcpModule()` */
	mcp?: McpAuthModule;
	/**
	 * The path prefix where TheAuth routes will be mounted.
	 * @default '/api/kavach'
	 */
	basePath?: string;
}

/** @deprecated Use {@link AuthModuleOptions} instead. Will be removed in v3.0. */
export type KavachModuleOptions = AuthModuleOptions;

// ─── AuthModule ────────────────────────────────────────────────────────────────

/**
 * NestJS dynamic module that mounts all TheAuth REST routes as Express
 * middleware. Import it once in your root `AppModule`.
 *
 * @example
 * ```typescript
 * // app.module.ts
 * import { Module } from '@nestjs/common';
 * import { AuthModule } from '@glinr/theauth-nestjs';
 * import { auth, mcp } from './lib/auth.js';
 *
 * @Module({
 *   imports: [
 *     AuthModule.forRoot({ kavach: auth, mcp, basePath: '/api/kavach' }),
 *   ],
 * })
 * export class AppModule {}
 * ```
 */
@Module({})
export class AuthModule implements NestModule {
	constructor(
		@Inject(AUTH_OPTIONS)
		private readonly options: AuthModuleOptions,
	) {}

	configure(consumer: MiddlewareConsumer): void {
		const basePath = this.options.basePath ?? "/api/kavach";
		consumer
			.apply(
				authMiddleware({
					kavach: this.options.kavach,
					mcp: this.options.mcp,
				}),
			)
			.forRoutes(`${basePath}/*path`);
	}

	static forRoot(options: AuthModuleOptions): DynamicModule {
		return {
			module: AuthModule,
			providers: [
				{
					provide: AUTH_OPTIONS,
					useValue: options,
				},
			],
		};
	}
}

/** @deprecated Use {@link AuthModule} instead. Will be removed in v3.0. */
export const KavachModule = AuthModule;
