import type {
	InputHTMLAttributes,
	ReactNode,
	SelectHTMLAttributes,
	TextareaHTMLAttributes,
} from "react";

// Label

interface LabelProps {
	htmlFor?: string;
	children: ReactNode;
	required?: boolean;
}

export function Label({ htmlFor, children, required }: LabelProps) {
	return (
		<label
			htmlFor={htmlFor}
			className="block text-xs font-medium text-zinc-600 dark:text-zinc-400 mb-1.5"
		>
			{children}
			{required && <span className="text-red-400 ml-1">*</span>}
		</label>
	);
}

// Input

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
	error?: string;
}

const BASE_INPUT =
	"w-full bg-white dark:bg-zinc-900 border border-zinc-300 dark:border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-900 dark:text-white placeholder-zinc-400 dark:placeholder-zinc-500 transition-colors focus:outline-none focus:ring-2 focus:ring-amber-500/30 focus:border-transparent disabled:opacity-50 disabled:cursor-not-allowed";

export function Input({ error, className = "", ...props }: InputProps) {
	return (
		<div>
			<input
				className={[BASE_INPUT, error ? "border-red-700" : "", className].join(" ")}
				{...props}
			/>
			{error && <p className="mt-1 text-xs text-red-400">{error}</p>}
		</div>
	);
}

// Select

interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
	error?: string;
	children: ReactNode;
}

export function Select({ error, className = "", children, ...props }: SelectProps) {
	return (
		<div>
			<select
				className={[
					BASE_INPUT,
					"appearance-none cursor-pointer",
					error ? "border-red-700" : "",
					className,
				].join(" ")}
				{...props}
			>
				{children}
			</select>
			{error && <p className="mt-1 text-xs text-red-400">{error}</p>}
		</div>
	);
}

// Textarea

interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
	error?: string;
}

export function Textarea({ error, className = "", ...props }: TextareaProps) {
	return (
		<div>
			<textarea
				className={[BASE_INPUT, "resize-none", error ? "border-red-700" : "", className].join(" ")}
				{...props}
			/>
			{error && <p className="mt-1 text-xs text-red-400">{error}</p>}
		</div>
	);
}

// Form Group

interface FormGroupProps {
	children: ReactNode;
	className?: string;
}

export function FormGroup({ children, className = "" }: FormGroupProps) {
	return <div className={["space-y-1", className].join(" ")}>{children}</div>;
}
