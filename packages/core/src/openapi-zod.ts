import type { ZodTypeAny } from "zod";

/** JSON Schema subset the generated OpenAPI document uses (OpenAPI 3.1, so `type` may be a list). */
export interface JsonSchema {
	$ref?: string;
	type?: string | string[];
	properties?: Record<string, JsonSchema>;
	required?: string[];
	items?: JsonSchema;
	enum?: Array<string | number | boolean>;
	const?: string | number | boolean;
	description?: string;
	format?: string;
	minimum?: number;
	minLength?: number;
	minItems?: number;
	additionalProperties?: JsonSchema | boolean;
	oneOf?: JsonSchema[];
	anyOf?: JsonSchema[];
	discriminator?: { propertyName: string };
}

interface ZodDef {
	typeName: string;
	description?: string;
	[key: string]: unknown;
}

function defOf(schema: ZodTypeAny): ZodDef {
	return schema._def as ZodDef;
}

/** Names registered components so a schema instance becomes a `$ref`. */
export type SchemaRegistry = ReadonlyMap<ZodTypeAny, string>;

function withNull(schema: JsonSchema): JsonSchema {
	if (schema.$ref) return { anyOf: [schema, { type: "null" }] };
	if (typeof schema.type === "string") return { ...schema, type: [schema.type, "null"] };
	return { anyOf: [schema, { type: "null" }] };
}

function describe(schema: JsonSchema, description: string | undefined): JsonSchema {
	return description && !schema.$ref ? { ...schema, description } : schema;
}

function numberSchema(def: ZodDef): JsonSchema {
	const checks = (def.checks as Array<{ kind: string; value?: number }> | undefined) ?? [];
	const out: JsonSchema = { type: checks.some((c) => c.kind === "int") ? "integer" : "number" };
	for (const check of checks) {
		if (check.kind === "min" && typeof check.value === "number") out.minimum = check.value;
	}
	return out;
}

function stringSchema(def: ZodDef): JsonSchema {
	const checks = (def.checks as Array<{ kind: string; value?: number }> | undefined) ?? [];
	const out: JsonSchema = { type: "string" };
	for (const check of checks) {
		if (check.kind === "min" && typeof check.value === "number") out.minLength = check.value;
	}
	return out;
}

/**
 * Convert the Zod subset the route table uses into JSON Schema. Throws on an unsupported
 * type, so a new schema shape fails the generator instead of producing a wrong document.
 * Optional properties are left out of `required`. Pass `skipRef` for the top-level schema of
 * a component so it expands instead of referencing itself.
 */
export function zodToJsonSchema(
	schema: ZodTypeAny,
	registry: SchemaRegistry,
	skipRef = false,
): JsonSchema {
	const named = registry.get(schema);
	if (named && !skipRef) return { $ref: `#/components/schemas/${named}` };
	const def = defOf(schema);
	const recurse = (inner: ZodTypeAny): JsonSchema => zodToJsonSchema(inner, registry);
	switch (def.typeName) {
		case "ZodString":
			return describe(stringSchema(def), def.description);
		case "ZodNumber":
			return describe(numberSchema(def), def.description);
		case "ZodBoolean":
			return describe({ type: "boolean" }, def.description);
		case "ZodDate":
			return describe({ type: "string", format: "date-time" }, def.description);
		case "ZodUnknown":
		case "ZodAny":
			return describe({}, def.description);
		case "ZodLiteral":
			return { const: def.value as string | number | boolean };
		case "ZodEnum":
			return describe({ type: "string", enum: [...(def.values as string[])] }, def.description);
		case "ZodNullable":
			return withNull(recurse(def.innerType as ZodTypeAny));
		case "ZodOptional":
		case "ZodDefault":
			return recurse(def.innerType as ZodTypeAny);
		case "ZodEffects":
			return recurse(def.schema as ZodTypeAny);
		case "ZodArray": {
			const out: JsonSchema = { type: "array", items: recurse(def.type as ZodTypeAny) };
			const min = def.minLength as { value: number } | null | undefined;
			if (min) out.minItems = min.value;
			return describe(out, def.description);
		}
		case "ZodRecord":
			return describe(
				{ type: "object", additionalProperties: recurse(def.valueType as ZodTypeAny) },
				def.description,
			);
		case "ZodUnion":
			return { oneOf: (def.options as ZodTypeAny[]).map(recurse) };
		case "ZodDiscriminatedUnion":
			return {
				oneOf: [...(def.options as Iterable<ZodTypeAny>)].map(recurse),
				discriminator: { propertyName: def.discriminator as string },
			};
		case "ZodObject": {
			const shape = (def.shape as () => Record<string, ZodTypeAny>)();
			const properties: Record<string, JsonSchema> = {};
			const required: string[] = [];
			for (const [key, value] of Object.entries(shape)) {
				properties[key] = recurse(value);
				if (!value.isOptional()) required.push(key);
			}
			const out: JsonSchema = { type: "object", properties };
			if (required.length > 0) out.required = required;
			return describe(out, def.description);
		}
		default:
			throw new Error(`openapi: unsupported zod type ${def.typeName}`);
	}
}
