"use client";

import { useSession } from "@theauth/react";
import Link from "next/link";

export default function HomePage() {
	const { session, isLoading } = useSession();
	const user = session?.user ?? null;

	return (
		<main
			style={{
				minHeight: "100vh",
				display: "flex",
				flexDirection: "column",
				alignItems: "center",
				justifyContent: "center",
				gap: "1.5rem",
				padding: "2rem",
				textAlign: "center",
			}}
		>
			<h1 style={{ fontSize: "2.5rem", fontWeight: 700, margin: 0 }}>__APP_NAME__</h1>
			<p style={{ color: "#888", margin: 0, maxWidth: "40ch" }}>
				Built on TheAuth &mdash; agent-first auth for the modern web.
			</p>

			<div style={{ display: "flex", gap: "1rem", flexWrap: "wrap", justifyContent: "center" }}>
				{isLoading ? null : user ? (
					<>
						<span style={{ color: "#888" }}>Signed in as {user.email}</span>
						<Link href="/api/auth/sign-out" style={ctaStyle("#333", "#ededed")}>
							Sign out
						</Link>
					</>
				) : (
					<Link href="/api/auth/sign-in" style={ctaStyle("#C9A84C", "#0a0a0a")}>
						Sign in
					</Link>
				)}

				<Link
					href={user ? "/agents" : "#"}
					aria-disabled={!user}
					style={ctaStyle(user ? "#C9A84C" : "#333", user ? "#0a0a0a" : "#666")}
					onClick={!user ? (e) => e.preventDefault() : undefined}
				>
					{user ? "My agents" : "Sign in to spawn an agent"}
				</Link>
			</div>
		</main>
	);
}

function ctaStyle(bg: string, color: string): React.CSSProperties {
	return {
		display: "inline-block",
		padding: "0.6rem 1.4rem",
		borderRadius: "0.5rem",
		background: bg,
		color,
		fontWeight: 600,
		textDecoration: "none",
		fontSize: "0.95rem",
	};
}
