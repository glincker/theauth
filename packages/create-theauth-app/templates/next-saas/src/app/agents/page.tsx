"use client";

import { useSession } from "@theauth/react";
import Link from "next/link";
import { useEffect, useState } from "react";

interface Agent {
	id: string;
	name: string;
	type: string;
	createdAt: string;
}

export default function AgentsPage() {
	const { session } = useSession();
	const [agents, setAgents] = useState<Agent[]>([]);
	const [loading, setLoading] = useState(true);

	useEffect(() => {
		if (!session?.user) {
			setLoading(false);
			return;
		}

		fetch("/api/agents")
			.then((r) => r.json())
			.then((data: { agents: Agent[] }) => setAgents(data.agents ?? []))
			.catch(() => setAgents([]))
			.finally(() => setLoading(false));
	}, [session]);

	if (!session?.user) {
		return (
			<main style={pageStyle}>
				<p>
					<Link href="/api/auth/sign-in">Sign in</Link> to manage your agents.
				</p>
			</main>
		);
	}

	return (
		<main style={pageStyle}>
			<h1 style={{ fontSize: "1.75rem", fontWeight: 700 }}>Your agents</h1>

			{loading ? (
				<p style={{ color: "#888" }}>Loading&hellip;</p>
			) : agents.length === 0 ? (
				<div style={{ textAlign: "center", color: "#888", marginTop: "4rem" }}>
					<p style={{ fontSize: "1.1rem" }}>No agents yet.</p>
					<Link
						href="/agents/new"
						style={{
							display: "inline-block",
							marginTop: "1rem",
							padding: "0.6rem 1.4rem",
							borderRadius: "0.5rem",
							background: "#C9A84C",
							color: "#0a0a0a",
							fontWeight: 600,
							textDecoration: "none",
						}}
					>
						Create first agent
					</Link>
				</div>
			) : (
				<ul style={{ listStyle: "none", padding: 0, margin: 0, width: "100%", maxWidth: "40rem" }}>
					{agents.map((agent) => (
						<li
							key={agent.id}
							style={{
								padding: "1rem",
								borderRadius: "0.5rem",
								background: "#111",
								marginBottom: "0.75rem",
								display: "flex",
								justifyContent: "space-between",
								alignItems: "center",
							}}
						>
							<div>
								<strong>{agent.name}</strong>
								<span style={{ marginLeft: "0.5rem", color: "#888", fontSize: "0.85rem" }}>
									{agent.type}
								</span>
							</div>
							<span style={{ color: "#555", fontSize: "0.8rem" }}>
								{new Date(agent.createdAt).toLocaleDateString()}
							</span>
						</li>
					))}
				</ul>
			)}
		</main>
	);
}

const pageStyle: React.CSSProperties = {
	minHeight: "100vh",
	display: "flex",
	flexDirection: "column",
	alignItems: "center",
	padding: "4rem 2rem",
	gap: "1.5rem",
};
