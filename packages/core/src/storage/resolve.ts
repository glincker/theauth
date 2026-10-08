import type { Database } from "../db/database.js";
import { withPrefix } from "./custom.js";
import { databaseStorage } from "./database.js";
import { memoryStorage } from "./memory.js";
import type {
	SecondaryStorage,
	SecondaryStorageConfig,
	SecondaryStorageFeature,
	SecondaryStorageOption,
	SecondaryStorageResolver,
} from "./types.js";
import { SECONDARY_STORAGE_FEATURES } from "./types.js";

function isFeatureMap(
	config: SecondaryStorageConfig,
): config is { default?: SecondaryStorageOption } & Partial<
	Record<SecondaryStorageFeature, SecondaryStorageOption>
> {
	return (
		typeof config === "object" &&
		config !== null &&
		typeof (config as Partial<SecondaryStorage>).get !== "function"
	);
}

/**
 * Turn the `secondaryStorage` config into a per-feature resolver.
 *
 * Resolution order for a feature: its own entry, then `default`, then a
 * process-local memory store. "database" uses the TheAuth database.
 * Each feature gets a `theauth:<feature>:` key prefix so features never collide
 * in a shared store. An instance is built once and reused.
 */
export function createSecondaryStorageResolver(
	config: SecondaryStorageConfig | undefined,
	db: Database,
): SecondaryStorageResolver {
	const memory = memoryStorage();
	let database: SecondaryStorage | null = null;

	function build(option: SecondaryStorageOption | undefined): SecondaryStorage {
		if (option === undefined || option === "memory") return memory;
		if (option === "database") {
			database ??= databaseStorage(db);
			return database;
		}
		return option;
	}

	const cache = new Map<SecondaryStorageFeature, SecondaryStorage>();

	return {
		for(feature) {
			const hit = cache.get(feature);
			if (hit) return hit;
			let option: SecondaryStorageOption | undefined;
			if (config === undefined) option = undefined;
			else if (isFeatureMap(config)) option = config[feature] ?? config.default;
			else option = config;
			const scoped = withPrefix(build(option), `theauth:${feature}:`);
			cache.set(feature, scoped);
			return scoped;
		},
	};
}

/** Throws a clear error for typos in per-feature keys (plain JS callers). */
export function assertSecondaryStorageConfig(config: SecondaryStorageConfig | undefined): void {
	if (config === undefined || !isFeatureMap(config)) return;
	for (const key of Object.keys(config)) {
		if (key !== "default" && !(SECONDARY_STORAGE_FEATURES as readonly string[]).includes(key)) {
			throw new Error(
				`secondaryStorage: unknown feature "${key}". Expected one of: default, ${SECONDARY_STORAGE_FEATURES.join(", ")}`,
			);
		}
	}
}
