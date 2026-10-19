import { createContext, useContext } from "react";
import type { TheAuthContextValue } from "./types.js";

export const TheAuthContext = createContext<TheAuthContextValue | null>(null);

export function useTheAuthContext(): TheAuthContextValue {
	const ctx = useContext(TheAuthContext);
	if (!ctx) {
		throw new Error("useTheAuthContext must be used inside <TheAuthProvider>");
	}
	return ctx;
}
