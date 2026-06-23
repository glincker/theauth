"use client";

import { AuthProvider } from "@glinr/theauth-react";
import type { ReactNode } from "react";

export function Providers({ children }: { children: ReactNode }) {
	return (
		<AuthProvider basePath="/api/kavach">{children}</AuthProvider>
	);
}
