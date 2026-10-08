import { defineConfig } from "tsup";

export default defineConfig([
	{
		entry: { bin: "src/bin.ts" },
		format: ["esm"],
		target: "node22",
		banner: { js: "#!/usr/bin/env node" },
	},
	{
		// Library entry for `import { loginWithDeviceFlow } from "@glinr/theauth-cli"`.
		entry: { index: "src/index.ts" },
		format: ["esm"],
		target: "node22",
		dts: true,
	},
]);
