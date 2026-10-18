/** Encoding helpers: deflate, base64 variants and PEM decoding. */

export async function deflateRawAsync(input: string): Promise<Uint8Array> {
	// Web standard API (Node 18+, Workers, Deno, Bun, browsers): keeps node:zlib out of the graph.
	const stream = new Blob([new TextEncoder().encode(input)])
		.stream()
		.pipeThrough(new CompressionStream("deflate-raw"));
	return new Uint8Array(await new Response(stream).arrayBuffer());
}

export function uint8ArrayToBase64(bytes: Uint8Array): string {
	let binary = "";
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i] as number);
	}
	return btoa(binary);
}

export function pemToArrayBuffer(pem: string): ArrayBuffer {
	const base64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes.buffer as ArrayBuffer;
}

export function base64ToArrayBuffer(b64: string): ArrayBuffer {
	let base64 = b64.replace(/-/g, "+").replace(/_/g, "/");
	while (base64.length % 4 !== 0) base64 += "=";
	const binary = atob(base64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes.buffer as ArrayBuffer;
}

export function uint8ArrayToBase64Url(bytes: Uint8Array): string {
	return uint8ArrayToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
