import { CheckCircle, Info, X, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";

// Types

type ToastVariant = "success" | "error" | "info";

interface Toast {
	id: string;
	variant: ToastVariant;
	message: string;
}

interface ToastContextValue {
	toast: (variant: ToastVariant, message: string) => void;
}

// Context

const ToastContext = createContext<ToastContextValue | null>(null);

// Config

const AUTO_DISMISS_MS = 3000;

const VARIANT_STYLES: Record<ToastVariant, string> = {
	success: "bg-zinc-50 dark:bg-zinc-900 border-emerald-700/60 text-emerald-400",
	error: "bg-zinc-50 dark:bg-zinc-900 border-red-700/60 text-red-400",
	info: "bg-zinc-50 dark:bg-zinc-900 border-amber-700/60 text-amber-400",
};

const VARIANT_ICONS: Record<ToastVariant, typeof CheckCircle> = {
	success: CheckCircle,
	error: XCircle,
	info: Info,
};

// Single Toast Item

interface ToastItemProps {
	toast: Toast;
	onDismiss: (id: string) => void;
}

function ToastItem({ toast, onDismiss }: ToastItemProps) {
	const Icon = VARIANT_ICONS[toast.variant];
	const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

	useEffect(() => {
		timerRef.current = setTimeout(() => onDismiss(toast.id), AUTO_DISMISS_MS);
		return () => {
			if (timerRef.current !== null) clearTimeout(timerRef.current);
		};
	}, [toast.id, onDismiss]);

	return (
		<div
			role="alert"
			className={[
				"flex items-start gap-3 px-4 py-3 rounded-xl border shadow-lg min-w-64 max-w-sm",
				"animate-in slide-in-from-bottom-2 fade-in duration-200",
				VARIANT_STYLES[toast.variant],
			].join(" ")}
		>
			<Icon className="w-4 h-4 flex-shrink-0 mt-0.5" strokeWidth={2} />
			<p className="flex-1 text-sm font-medium text-zinc-800 dark:text-zinc-200">{toast.message}</p>
			<button
				type="button"
				onClick={() => onDismiss(toast.id)}
				className="flex-shrink-0 text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors"
				aria-label="Dismiss notification"
			>
				<X className="w-3.5 h-3.5" />
			</button>
		</div>
	);
}

// Provider

interface ToastProviderProps {
	children: ReactNode;
}

export function ToastProvider({ children }: ToastProviderProps) {
	const [toasts, setToasts] = useState<Toast[]>([]);

	const dismiss = useCallback((id: string) => {
		setToasts((prev) => prev.filter((t) => t.id !== id));
	}, []);

	const toast = useCallback((variant: ToastVariant, message: string) => {
		const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
		setToasts((prev) => [...prev, { id, variant, message }]);
	}, []);

	return (
		<ToastContext.Provider value={{ toast }}>
			{children}
			{toasts.length > 0 && (
				<div
					role="status"
					aria-label="Notifications"
					className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 items-end"
				>
					{toasts.map((t) => (
						<ToastItem key={t.id} toast={t} onDismiss={dismiss} />
					))}
				</div>
			)}
		</ToastContext.Provider>
	);
}

// Hook

export function useToast(): ToastContextValue {
	const ctx = useContext(ToastContext);
	if (ctx === null) {
		throw new Error("useToast must be used inside <ToastProvider>");
	}
	return ctx;
}
