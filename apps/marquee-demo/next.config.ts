import type { NextConfig } from "next";

const nextConfig: NextConfig = {
	transpilePackages: ["kavachos"],
	webpack(config, { isServer }) {
		// sql.js requires WASM and fs access, only run it server-side.
		// Silence the warning about missing WASM binaries on the client bundle.
		if (!isServer) {
			config.resolve = {
				...config.resolve,
				fallback: {
					...(config.resolve?.fallback ?? {}),
					fs: false,
					path: false,
					crypto: false,
				},
			};
		}

		// Allow .wasm imports for sql.js
		config.experiments = {
			...config.experiments,
			asyncWebAssembly: true,
		};

		return config;
	},
};

export default nextConfig;
