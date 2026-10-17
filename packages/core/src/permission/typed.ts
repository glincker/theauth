import type { ExplainOptions } from "../explain/types.js";
import type { TheAuth } from "../theauth-core.js";
import type {
	AuthorizeRequest,
	AuthorizeResult,
	CreateAgentInput,
	DelegateInput,
	DelegationChain,
	Permission,
	RequestContext,
	UpdateAgentInput,
} from "../types.js";

/** Resource pattern to allowed actions. Patterns use the same ":" and "*" rules as the runtime resource matcher. */
export type PermissionCatalog = Readonly<Record<string, readonly string[]>>;

/** Identity helper that keeps literal types, so the catalog can drive `createTheAuth` inference. */
export function definePermissions<const C extends PermissionCatalog>(catalog: C): C {
	return catalog;
}

/** "mcp:github:*" becomes `mcp:github:${string}`, "*" becomes string, exact patterns stay literal. */
export type ResourceOf<Pattern extends string> = Pattern extends "*"
	? string
	: Pattern extends `${infer Prefix}*`
		? `${Prefix}${string}`
		: Pattern;

/** Correlated (resource, action) pairs: an action is only allowed with a resource its pattern covers. */
export type TypedAuthorizeRequest<C extends PermissionCatalog> = {
	[P in keyof C & string]: Omit<AuthorizeRequest, "action" | "resource"> & {
		resource: ResourceOf<P>;
		action: C[P][number];
	};
}[keyof C & string];

export type TypedPermission<C extends PermissionCatalog> = {
	[P in keyof C & string]: Omit<Permission, "resource" | "actions"> & {
		/** Exact pattern or any narrower pattern of the declared one. */
		resource: P | ResourceOf<P>;
		actions: ReadonlyArray<C[P][number] | "*">;
	};
}[keyof C & string];

/** Correlated (action, resource, options) positional arguments for `explain`, same rules as TypedAuthorizeRequest. */
export type TypedExplainArgs<C extends PermissionCatalog> = {
	[P in keyof C & string]: [
		action: C[P][number],
		resource: ResourceOf<P>,
		options?: ExplainOptions,
	];
}[keyof C & string];

type TypedCreateAgentInput<C extends PermissionCatalog> = Omit<CreateAgentInput, "permissions"> & {
	permissions: TypedPermission<C>[];
};

type TypedUpdateAgentInput<C extends PermissionCatalog> = Omit<UpdateAgentInput, "permissions"> & {
	permissions?: TypedPermission<C>[];
};

type TypedDelegateInput<C extends PermissionCatalog> = Omit<DelegateInput, "permissions"> & {
	permissions: TypedPermission<C>[];
};

/**
 * Facade over `TheAuth` with `resource` and `action` narrowed to a declared catalog.
 * Non permission members are unchanged. Cast to `TheAuth` to pass it to adapters.
 */
export type TypedTheAuth<C extends PermissionCatalog> = Omit<
	TheAuth,
	"authorize" | "authorizeByToken" | "delegate" | "agent" | "explain"
> & {
	explain(agentId: string, ...args: TypedExplainArgs<C>): ReturnType<TheAuth["explain"]>;
	authorize(
		agentId: string,
		request: TypedAuthorizeRequest<C>,
		context?: RequestContext,
	): Promise<AuthorizeResult>;
	authorizeByToken(
		token: string,
		request: TypedAuthorizeRequest<C>,
		context?: RequestContext,
	): Promise<AuthorizeResult>;
	delegate(input: TypedDelegateInput<C>): Promise<DelegationChain>;
	agent: Omit<TheAuth["agent"], "create" | "update"> & {
		create(input: TypedCreateAgentInput<C>): ReturnType<TheAuth["agent"]["create"]>;
		update(
			agentId: string,
			input: TypedUpdateAgentInput<C>,
		): ReturnType<TheAuth["agent"]["update"]>;
	};
};
