"use client";

interface CodeBlockProps {
	value: unknown;
}

export function CodeBlock({ value }: CodeBlockProps) {
	return (
		<pre className="code-scroll overflow-x-auto p-4 text-xs font-mono text-zinc-300 bg-zinc-950 leading-relaxed">
			{JSON.stringify(value, null, 2)}
		</pre>
	);
}
