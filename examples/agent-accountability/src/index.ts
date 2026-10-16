import { runAccountabilityLoop } from "./loop.js";

/** Deliberate demo transcript output: this is the product of the example. */
function step(n: number, text: string): void {
	console.log(`\n[${n}] ${text}`);
}

function note(text: string): void {
	console.log(`    ${text}`);
}

runAccountabilityLoop({ step, note }).catch((err: unknown) => {
	console.error("Fatal error:", err);
	process.exit(1);
});
