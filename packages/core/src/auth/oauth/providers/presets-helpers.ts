import { trimTrailingSlashes } from "../../../trim-slashes.js";

export function trimUrl(url: string): string {
	return trimTrailingSlashes(url);
}

export function str(value: unknown): string | undefined {
	return typeof value === "string" && value.length > 0 ? value : undefined;
}
