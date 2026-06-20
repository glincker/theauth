import type { Metadata } from "next";
import { Providers } from "./providers";
import "./globals.css";

export const metadata: Metadata = {
	title: "TheAuth Demo",
	description: "Reference implementation for TheAuth auth and agent features",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
	return (
		<html lang="en">
			<body className="bg-zinc-950 text-zinc-100 antialiased">
				<Providers>{children}</Providers>
			</body>
		</html>
	);
}
