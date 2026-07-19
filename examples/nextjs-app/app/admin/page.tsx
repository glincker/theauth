"use client";
import { TheAuthDashboard } from "@glinr/theauth-dashboard";

export default function AdminPage() {
	return <TheAuthDashboard apiUrl="/api/theauth" theme="dark" />;
}
