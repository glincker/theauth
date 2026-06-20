"use client";

import { KavachProvider } from "@theauth/react";
import type { ReactNode } from "react";

export function Providers({ children }: { children: ReactNode }) {
	return (
		<KavachProvider basePath="/api/kavach">{children}</KavachProvider>
	);
}
