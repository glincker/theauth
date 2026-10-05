import { useCallback, useRef, useState } from "react";
import type { RunAction } from "./shared.js";
import { CODE_RECENT_AUTH_REQUIRED, errorCodeOf } from "./shared.js";

export interface StepUpDialogBinding {
	open: boolean;
	onClose: () => void;
	onElevated: () => void;
}

/**
 * Wraps sensitive actions: when one fails with auth.recent_auth_required the dialog opens,
 * and the action is retried once after a successful step-up.
 */
export function useStepUpRetry(): { run: RunAction; dialogProps: StepUpDialogBinding } {
	const [open, setOpen] = useState(false);
	const pending = useRef<(() => Promise<unknown>) | null>(null);

	const run: RunAction = useCallback(async (action) => {
		try {
			return await action();
		} catch (error) {
			if (errorCodeOf(error) !== CODE_RECENT_AUTH_REQUIRED) throw error;
			pending.current = action;
			setOpen(true);
			return undefined;
		}
	}, []);

	const onClose = useCallback(() => {
		pending.current = null;
		setOpen(false);
	}, []);

	const onElevated = useCallback(() => {
		const action = pending.current;
		pending.current = null;
		setOpen(false);
		if (action) void action().catch(() => undefined);
	}, []);

	return { run, dialogProps: { open, onClose, onElevated } };
}
