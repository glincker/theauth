import Link from "next/link";

export default function HomePage() {
	return (
		<main
			style={{
				fontFamily: "Inter, system-ui, sans-serif",
				background: "#0f0f0f",
				color: "#e5e5e5",
				minHeight: "100vh",
				padding: "48px 24px",
				lineHeight: 1.6,
			}}
		>
			<div style={{ maxWidth: 640, margin: "0 auto" }}>
				<h1
					style={{
						fontSize: "1.75rem",
						fontWeight: 700,
						color: "#C9A84C",
						marginBottom: 8,
					}}
				>
					TheAuth
				</h1>
				<p style={{ color: "#888", marginBottom: 40, fontSize: "0.95rem" }}>
					Auth OS for AI agents — agent identity, permissions, delegation, audit.
				</p>

				<ul style={{ listStyle: "none", padding: 0 }}>
					<li style={{ marginBottom: 12 }}>
						<Link
							href="/admin"
							style={{ color: "#C9A84C", textDecoration: "none", fontSize: "0.95rem" }}
						>
							/admin — TheAuth dashboard
						</Link>
						<span style={{ color: "#555", marginLeft: 12, fontSize: "0.82rem" }}>
							embedded React UI
						</span>
					</li>
					<li style={{ marginBottom: 12 }}>
						<Link
							href="/api/theauth/agents"
							style={{ color: "#C9A84C", textDecoration: "none", fontSize: "0.95rem" }}
						>
							/api/theauth/agents
						</Link>
						<span style={{ color: "#555", marginLeft: 12, fontSize: "0.82rem" }}>
							list all agents (JSON)
						</span>
					</li>
					<li style={{ marginBottom: 12 }}>
						<Link
							href="/api/theauth/audit"
							style={{ color: "#C9A84C", textDecoration: "none", fontSize: "0.95rem" }}
						>
							/api/theauth/audit
						</Link>
						<span style={{ color: "#555", marginLeft: 12, fontSize: "0.82rem" }}>
							query audit logs (JSON)
						</span>
					</li>
					<li style={{ marginBottom: 12 }}>
						<Link
							href="/api/theauth/dashboard/stats"
							style={{ color: "#C9A84C", textDecoration: "none", fontSize: "0.95rem" }}
						>
							/api/theauth/dashboard/stats
						</Link>
						<span style={{ color: "#555", marginLeft: 12, fontSize: "0.82rem" }}>
							summary stats (JSON)
						</span>
					</li>
				</ul>
			</div>
		</main>
	);
}
