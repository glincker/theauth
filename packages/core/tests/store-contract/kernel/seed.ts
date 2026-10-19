import type { StoreKernel } from "../../../src/db/store/index.js";
import { uid } from "./target.js";

export async function seedUser(kernel: StoreKernel): Promise<string> {
	const id = uid("u");
	const now = new Date();
	await kernel.insert("users", {
		id,
		email: `${id}@kernel.test`,
		name: null,
		metadata: null,
		createdAt: now,
		updatedAt: now,
	});
	return id;
}

export async function seedAgent(kernel: StoreKernel): Promise<{ agentId: string; userId: string }> {
	const userId = await seedUser(kernel);
	const agentId = uid("a");
	const now = new Date();
	await kernel.insert("agents", {
		id: agentId,
		ownerId: userId,
		name: "contract agent",
		type: "autonomous",
		tokenHash: uid("h"),
		tokenPrefix: "pfx",
		createdAt: now,
		updatedAt: now,
	});
	return { agentId, userId };
}
