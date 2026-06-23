"use client";
import { AuthDashboard } from "@glinr/theauth-dashboard";

export default function AdminPage() {
	return <AuthDashboard apiUrl="/api/kavach" theme="dark" />;
}
