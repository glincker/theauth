export function isPasskeySupported(): boolean {
	return (
		typeof window !== "undefined" &&
		typeof window.PublicKeyCredential !== "undefined" &&
		typeof navigator !== "undefined" &&
		typeof navigator.credentials !== "undefined"
	);
}

export function base64UrlToBuffer(value: string): ArrayBuffer {
	const padded = value.replace(/-/g, "+").replace(/_/g, "/");
	const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes.buffer;
}

export function bufferToBase64Url(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface DescriptorJSON {
	id: string;
	type: PublicKeyCredentialType;
	transports?: AuthenticatorTransport[];
}

export interface CreationOptionsJSON {
	publicKey: Omit<
		PublicKeyCredentialCreationOptions,
		"challenge" | "user" | "excludeCredentials"
	> & {
		challenge: string;
		user: Omit<PublicKeyCredentialUserEntity, "id"> & { id: string };
		excludeCredentials?: DescriptorJSON[];
	};
}

export interface RequestOptionsJSON {
	publicKey: Omit<PublicKeyCredentialRequestOptions, "challenge" | "allowCredentials"> & {
		challenge: string;
		allowCredentials?: DescriptorJSON[];
	};
}

function descriptor(d: DescriptorJSON): PublicKeyCredentialDescriptor {
	return { ...d, id: base64UrlToBuffer(d.id) };
}

export function creationOptionsFromJSON(
	json: CreationOptionsJSON,
): PublicKeyCredentialCreationOptions {
	const { challenge, user, excludeCredentials, ...rest } = json.publicKey;
	return {
		...rest,
		challenge: base64UrlToBuffer(challenge),
		user: { ...user, id: base64UrlToBuffer(user.id) },
		excludeCredentials: excludeCredentials?.map(descriptor),
	};
}

export function requestOptionsFromJSON(
	json: RequestOptionsJSON,
): PublicKeyCredentialRequestOptions {
	const { challenge, allowCredentials, ...rest } = json.publicKey;
	return {
		...rest,
		challenge: base64UrlToBuffer(challenge),
		allowCredentials: allowCredentials?.map(descriptor),
	};
}

export function attestationToJSON(cred: PublicKeyCredential): Record<string, unknown> {
	const response = cred.response as AuthenticatorAttestationResponse;
	return {
		id: cred.id,
		rawId: bufferToBase64Url(cred.rawId),
		type: cred.type,
		authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
		clientExtensionResults: cred.getClientExtensionResults(),
		response: {
			clientDataJSON: bufferToBase64Url(response.clientDataJSON),
			attestationObject: bufferToBase64Url(response.attestationObject),
			transports: response.getTransports?.() ?? [],
		},
	};
}

export function assertionToJSON(cred: PublicKeyCredential): Record<string, unknown> {
	const response = cred.response as AuthenticatorAssertionResponse;
	return {
		id: cred.id,
		rawId: bufferToBase64Url(cred.rawId),
		type: cred.type,
		authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
		clientExtensionResults: cred.getClientExtensionResults(),
		response: {
			clientDataJSON: bufferToBase64Url(response.clientDataJSON),
			authenticatorData: bufferToBase64Url(response.authenticatorData),
			signature: bufferToBase64Url(response.signature),
			userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : null,
		},
	};
}
