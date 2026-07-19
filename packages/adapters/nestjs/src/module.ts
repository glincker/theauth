import type { TheAuth } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import type { DynamicModule, MiddlewareConsumer, NestModule } from "@nestjs/common";
import { Inject, Module } from "@nestjs/common";
import { theAuthMiddleware } from "./adapter.js";

// ─── Injection Token ──────────────────────────────────────────────────────────

const AUTH_OPTIONS = Symbol("AUTH_OPTIONS");

// ─── Module Options ───────────────────────────────────────────────────────────

export interface TheAuthModuleOptions {
	/** The TheAuth instance created with `createTheAuth()` */
	kavach: TheAuth;
	/** Optional MCP OAuth 2.1 module created with `createMcpModule()` */
	mcp?: McpAuthModule;
	/**
	 * The path prefix where TheAuth routes will be mounted.
	 * @default '/api/kavach'
	 */
	basePath?: string;
}

/** @deprecated Use `TheAuthModuleOptions` instead. Will be removed in a future major version. */
export type AuthModuleOptions = TheAuthModuleOptions;

/** @deprecated Use `TheAuthModuleOptions` instead. Will be removed in a future major version. */
export type KavachModuleOptions = TheAuthModuleOptions;

// ─── TheAuthModule ────────────────────────────────────────────────────────────

/**
 * NestJS dynamic module that mounts all TheAuth REST routes as Express
 * middleware. Import it once in your root `AppModule`.
 *
 * @example
 * ```typescript
 * // app.module.ts
 * import { Module } from '@nestjs/common';
 * import { TheAuthModule } from '@glinr/theauth-nestjs';
 * import { auth, mcp } from './lib/auth.js';
 *
 * @Module({
 *   imports: [
 *     TheAuthModule.forRoot({ kavach: auth, mcp, basePath: '/api/kavach' }),
 *   ],
 * })
 * export class AppModule {}
 * ```
 */
@Module({})
export class TheAuthModule implements NestModule {
	constructor(
		@Inject(AUTH_OPTIONS)
		private readonly options: TheAuthModuleOptions,
	) {}

	configure(consumer: MiddlewareConsumer): void {
		const basePath = this.options.basePath ?? "/api/kavach";
		consumer
			.apply(
				theAuthMiddleware({
					kavach: this.options.kavach,
					mcp: this.options.mcp,
				}),
			)
			.forRoutes(`${basePath}/*path`);
	}

	static forRoot(options: TheAuthModuleOptions): DynamicModule {
		return {
			module: TheAuthModule,
			providers: [
				{
					provide: AUTH_OPTIONS,
					useValue: options,
				},
			],
		};
	}
}

/** @deprecated Use `TheAuthModule` instead. Will be removed in a future major version. */
export const AuthModule = TheAuthModule;

/** @deprecated Use `TheAuthModule` instead. Will be removed in a future major version. */
export const KavachModule = TheAuthModule;
