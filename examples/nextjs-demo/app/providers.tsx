"use client";

import { TheAuthProvider } from "@glinr/theauth-react";
import type { ReactNode } from "react";

export function Providers({ children }: { children: ReactNode }) {
	return (
		<TheAuthProvider basePath="/api/theauth">{children}</TheAuthProvider>
	);
}
