"use client";
import { KavachDashboard } from "@glinr/theauth-dashboard";

export default function AdminPage() {
	return <KavachDashboard apiUrl="/api/theauth" theme="dark" />;
}
