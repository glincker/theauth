"use client";
import { KavachDashboard } from "@theauth/dashboard";

export default function AdminPage() {
	return <KavachDashboard apiUrl="/api/kavach" theme="dark" />;
}
