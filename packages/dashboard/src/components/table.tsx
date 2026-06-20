import { ExternalLink } from "lucide-react";
import type { ReactNode } from "react";

interface TableProps {
	children: ReactNode;
}

interface TableHeadProps {
	children: ReactNode;
}

interface TableBodyProps {
	children: ReactNode;
}

interface ThProps {
	children?: ReactNode;
	className?: string;
}

interface TdProps {
	children: ReactNode;
	className?: string;
}

interface TrProps {
	children: ReactNode;
	onClick?: () => void;
}

export function Table({ children }: TableProps) {
	return (
		<div className="rounded-xl border border-zinc-200 dark:border-zinc-800 overflow-hidden">
			<table className="w-full text-sm">{children}</table>
		</div>
	);
}

export function TableHead({ children }: TableHeadProps) {
	return (
		<thead className="bg-zinc-100 dark:bg-zinc-900 border-b border-zinc-200 dark:border-zinc-800">
			<tr>{children}</tr>
		</thead>
	);
}

export function TableBody({ children }: TableBodyProps) {
	return <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60">{children}</tbody>;
}

export function Th({ children, className = "" }: ThProps) {
	return (
		<th
			className={[
				"px-4 py-3 text-left text-xs font-medium text-zinc-500 uppercase tracking-wider",
				className,
			].join(" ")}
		>
			{children}
		</th>
	);
}

export function Td({ children, className = "" }: TdProps) {
	return (
		<td className={["px-4 py-3 text-zinc-600 dark:text-zinc-300", className].join(" ")}>
			{children}
		</td>
	);
}

export function Tr({ children, onClick }: TrProps) {
	return (
		<tr
			onClick={onClick}
			className={[
				"bg-white dark:bg-zinc-950 transition-colors",
				onClick ? "cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-900" : "",
			].join(" ")}
		>
			{children}
		</tr>
	);
}

// ─── Empty State ──────────────────────────────────────────────────────────────

interface EmptyStateProps {
	icon: ReactNode;
	title: string;
	description?: string;
	action?: ReactNode;
	steps?: string[];
	docsLink?: string;
}

export function EmptyState({ icon, title, description, action, steps, docsLink }: EmptyStateProps) {
	return (
		<div className="flex flex-col items-center justify-center py-16 text-center">
			<div className="w-12 h-12 rounded-xl bg-zinc-100 dark:bg-zinc-800 flex items-center justify-center mb-4 text-zinc-400 dark:text-zinc-500">
				{icon}
			</div>
			<p className="text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">{title}</p>
			{description && <p className="text-xs text-zinc-500 max-w-xs mb-4">{description}</p>}
			{steps && steps.length > 0 && (
				<ol className="text-left mt-2 mb-5 space-y-1.5 max-w-xs">
					{steps.map((step, i) => (
						<li key={step} className="flex items-start gap-2.5 text-xs text-zinc-500">
							<span className="flex-shrink-0 w-4 h-4 rounded-full bg-zinc-100 dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 flex items-center justify-center text-[10px] font-medium text-zinc-500 dark:text-zinc-400 mt-px">
								{i + 1}
							</span>
							<span>{step}</span>
						</li>
					))}
				</ol>
			)}
			{action}
			{docsLink && (
				<a
					href={docsLink}
					target="_blank"
					rel="noopener noreferrer"
					aria-label={`View ${title} documentation`}
					className="inline-flex items-center gap-1 mt-4 text-xs text-zinc-400 dark:text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-700 dark:hover:text-zinc-300 transition-colors"
				>
					View documentation
					<ExternalLink className="w-3 h-3" />
				</a>
			)}
		</div>
	);
}
