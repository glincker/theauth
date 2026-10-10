import type { AdapterSecurityOptions, TheAuth } from "@glinr/theauth";
import type { McpAuthModule } from "@glinr/theauth/mcp";
import type { DynamicModule, MiddlewareConsumer, NestModule } from "@nestjs/common";
import { Inject, Module } from "@nestjs/common";
import { theAuthMiddleware } from "./adapter.js";

// ─── Injection Token ──────────────────────────────────────────────────────────

const AUTH_OPTIONS = Symbol("AUTH_OPTIONS");

// ─── Module Options ───────────────────────────────────────────────────────────

export interface TheAuthModuleOptions extends AdapterSecurityOptions {
	/** The TheAuth instance created with `createTheAuth()` */
	theauth: TheAuth;
	/** Optional MCP OAuth 2.1 module created with `createMcpModule()` */
	mcp?: McpAuthModule;
	/**
	 * The path prefix where TheAuth routes will be mounted.
	 * @default '/api/theauth'
	 */
	basePath?: string;
}

/** @deprecated Use `TheAuthModuleOptions` instead. Will be removed in a future major version. */
export type AuthModuleOptions = TheAuthModuleOptions;

// ─── Security option passthrough ──────────────────────────────────────────────

/**
 * Every `AdapterSecurityOptions` key. Typed as a full record so adding a key to
 * the core interface fails the build here until it is listed.
 */
const SECURITY_OPTION_KEYS: Record<keyof AdapterSecurityOptions, true> = {
	authenticate: true,
	allowUnauthenticated: true,
	trustedProxy: true,
};

function pickSecurityOptions(options: AdapterSecurityOptions): AdapterSecurityOptions {
	const picked: AdapterSecurityOptions = {};
	for (const key of Object.keys(SECURITY_OPTION_KEYS) as Array<keyof AdapterSecurityOptions>) {
		if (options[key] !== undefined) Object.assign(picked, { [key]: options[key] });
	}
	return picked;
}

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
 *     TheAuthModule.forRoot({ theauth: auth, mcp, basePath: '/api/theauth' }),
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
		const basePath = this.options.basePath ?? "/api/theauth";
		consumer
			.apply(
				theAuthMiddleware({
					theauth: this.options.theauth,
					mcp: this.options.mcp,
					...pickSecurityOptions(this.options),
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
