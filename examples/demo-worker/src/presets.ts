import type { Permission } from "@glinr/theauth";

export type PresetId = "reader" | "editor";

export interface Preset {
	id: PresetId;
	label: string;
	description: string;
	permissions: Permission[];
}

export const PRESETS: readonly Preset[] = [
	{
		id: "reader",
		label: "Reader",
		description: "Can read anything under docs. Cannot write.",
		permissions: [{ resource: "docs:*", actions: ["read"] }],
	},
	{
		id: "editor",
		label: "Editor",
		description: "Can read and write under docs, and read crm:contacts.",
		permissions: [
			{ resource: "docs:*", actions: ["read", "write"] },
			{ resource: "crm:contacts", actions: ["read"] },
		],
	},
];

export function findPreset(id: string): Preset | undefined {
	return PRESETS.find((p) => p.id === id);
}
