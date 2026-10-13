import { createAuthClient } from "./vendor/theauth-extension.js";

const auth = createAuthClient();
const status = document.getElementById("status");

function show(text) {
	if (status) status.textContent = text;
}

async function refresh() {
	try {
		const session = await auth.getSession();
		show(session ? `Signed in, scopes: ${session.scope}` : "Signed out");
	} catch (error) {
		show(`Error: ${error.code ?? "unknown"}`);
	}
}

document.getElementById("sign-in")?.addEventListener("click", async () => {
	try {
		await auth.signIn();
	} catch (error) {
		show(`Sign in failed: ${error.code ?? "unknown"}`);
		return;
	}
	await refresh();
});

document.getElementById("sign-out")?.addEventListener("click", async () => {
	await auth.signOut();
	await refresh();
});

void refresh();
