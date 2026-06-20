import { KavachProvider } from "@theauth/react";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata = {
	title: "__APP_NAME__",
	description: "Powered by TheAuth",
};

export default function RootLayout({ children }: { children: ReactNode }) {
	return (
		<html lang="en">
			<body>
				<KavachProvider basePath="/api/auth">{children}</KavachProvider>
			</body>
		</html>
	);
}
