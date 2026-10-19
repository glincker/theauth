import { generateOpenAPISpec } from "./openapi.js";

/** The checked-in `sdks/openapi.json` text: default options, two space indent, trailing newline. */
export function renderOpenAPIJson(): string {
	return `${JSON.stringify(generateOpenAPISpec(), null, 2)}\n`;
}
