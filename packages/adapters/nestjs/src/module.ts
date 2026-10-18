import type { TheAuth } from "@glinr/theauth";
import type { TheAuthHandlerOptions } from "@glinr/theauth/http";
import type { DynamicModule, MiddlewareConsumer, NestModule } from "@nestjs/common";
import { Inject, Module } from "@nestjs/common";
import { theAuthMiddleware } from "./adapter.js";

const AUTH_OPTIONS = Symbol("AUTH_OPTIONS");

export interface TheAuthModuleOptions extends TheAuthHandlerOptions {
	theauth: TheAuth;
}

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
		const { theauth, ...handlerOptions } = this.options;
		const basePath = handlerOptions.basePath ?? "/api/theauth";
		consumer
			.apply(theAuthMiddleware({ ...handlerOptions, theauth, basePath }))
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
