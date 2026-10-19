export type {
	SpiffeAuthFailure,
	SpiffeAuthResult,
	SpiffeBridge,
	SpiffeBridgeConfig,
	SpiffePresentation,
	SpiffePrincipal,
} from "./bridge.js";
export { createSpiffeBridge } from "./bridge.js";
export type { BundleParseResult, SpiffeBundle } from "./bundle.js";
export { bundleFromRoots, parseSpiffeBundle } from "./bundle.js";
export type {
	BundleRefresh,
	SpiffeBundleEndpoint,
	SpiffeBundleStore,
	SpiffeTrustDomainConfig,
} from "./bundle-store.js";
export { createBundleStore } from "./bundle-store.js";
export type { JwtSvidIdentity, JwtSvidOptions, JwtSvidResult } from "./jwt-svid.js";
export { verifyJwtSvid } from "./jwt-svid.js";
export type { SpiffeId, SpiffeIdResult } from "./spiffe-id.js";
export { MAX_SPIFFE_ID_BYTES, parseSpiffeId, parseTrustDomain } from "./spiffe-id.js";
export type {
	SvidFailure,
	X509SvidIdentity,
	X509SvidOptions,
	X509SvidResult,
} from "./x509-svid.js";
export { certThumbprint, verifyX509Svid } from "./x509-svid.js";
