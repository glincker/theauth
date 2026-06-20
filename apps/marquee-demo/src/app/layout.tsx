import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
	title: "TheAuth, live demo",
	description:
		"Interactive demo: passkey sign-up, agent spawning, scoped tool calls, delegation, and an EU AI Act audit export.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
	return (
		<html lang="en" className="dark">
			<body>{children}</body>
		</html>
	);
}
