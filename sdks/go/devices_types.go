package theauth

import "errors"

// DeviceStatus is the lifecycle state of a device.
type DeviceStatus string

const (
	DeviceActive    DeviceStatus = "active"
	DeviceSuspended DeviceStatus = "suspended"
	DeviceRevoked   DeviceStatus = "revoked"
)

// DeviceCredentialKind is how a device proves itself.
type DeviceCredentialKind string

const (
	DeviceCredentialPSK  DeviceCredentialKind = "psk"
	DeviceCredentialJWK  DeviceCredentialKind = "jwk"
	DeviceCredentialX509 DeviceCredentialKind = "x509"
	// DeviceCredentialSPIFFE is a linked SPIFFE ID, added with LinkSPIFFEID.
	DeviceCredentialSPIFFE DeviceCredentialKind = "spiffe"
)

// EnrollmentKind is a claim code (one device) or a bulk token (a fleet rollout).
type EnrollmentKind string

const (
	EnrollmentClaim EnrollmentKind = "claim"
	EnrollmentBulk  EnrollmentKind = "bulk"
)

// CredentialSpec is the credential a device is registered or enrolled with.
// Build one with PSKCredential, JWKCredential or X509Credential.
type CredentialSpec struct {
	Kind       DeviceCredentialKind `json:"kind"`
	JWK        map[string]string    `json:"jwk,omitempty"`
	Thumbprint string               `json:"thumbprint,omitempty"`
}

// PSKCredential asks the server for a fresh pre shared key. It comes back
// once, as DeviceCredential.Secret.
func PSKCredential() CredentialSpec { return CredentialSpec{Kind: DeviceCredentialPSK} }

// JWKCredential registers the public half of a device key (EC P-256, EC P-384
// or Ed25519). A JWK with a private member (d) is refused before it leaves the
// process.
func JWKCredential(publicJWK map[string]string) (CredentialSpec, error) {
	if _, ok := publicJWK["d"]; ok {
		return CredentialSpec{}, errors.New("theauth: pass the public JWK only, never the private key")
	}
	cp := make(map[string]string, len(publicJWK))
	for k, v := range publicJWK {
		cp[k] = v
	}
	return CredentialSpec{Kind: DeviceCredentialJWK, JWK: cp}, nil
}

// X509Credential registers a client certificate by its x5t#S256 thumbprint (RFC 8705).
func X509Credential(thumbprint string) CredentialSpec {
	return CredentialSpec{Kind: DeviceCredentialX509, Thumbprint: thumbprint}
}

// DeviceCredential is one credential row. Secret is set only on the call that
// created a PSK.
type DeviceCredential struct {
	ID         string                 `json:"id"`
	DeviceID   string                 `json:"deviceId"`
	Kind       DeviceCredentialKind   `json:"kind"`
	Lookup     string                 `json:"lookup"`
	PublicJWK  map[string]interface{} `json:"publicJwk,omitempty"`
	Status     string                 `json:"status"`
	ExpiresAt  *string                `json:"expiresAt"`
	LastUsedAt *string                `json:"lastUsedAt"`
	CreatedAt  string                 `json:"createdAt"`
	Secret     string                 `json:"secret,omitempty"`
}

// Device is a device and the agent behind it (AgentID holds permissions,
// delegations and audit rows).
type Device struct {
	ID           string                 `json:"id"`
	AgentID      string                 `json:"agentId"`
	OwnerID      string                 `json:"ownerId"`
	TenantID     string                 `json:"tenantId,omitempty"`
	Name         string                 `json:"name"`
	Kind         string                 `json:"kind,omitempty"`
	HardwareID   string                 `json:"hardwareId,omitempty"`
	Status       DeviceStatus           `json:"status"`
	StatusReason string                 `json:"statusReason,omitempty"`
	Groups       []string               `json:"groups"`
	Permissions  []Permission           `json:"permissions"`
	Metadata     map[string]interface{} `json:"metadata"`
	EnrollmentID string                 `json:"enrollmentId,omitempty"`
	Attestation  map[string]interface{} `json:"attestation,omitempty"`
	ExpiresAt    *string                `json:"expiresAt"`
	LastSeenAt   *string                `json:"lastSeenAt"`
	LastSeenIP   string                 `json:"lastSeenIp,omitempty"`
	CreatedAt    string                 `json:"createdAt"`
	UpdatedAt    string                 `json:"updatedAt"`
}

// DeviceRegistration is returned by register and enroll: the device, and its
// credential when one was made.
type DeviceRegistration struct {
	Device     Device            `json:"device"`
	Credential *DeviceCredential `json:"credential,omitempty"`
}

// RegisterDeviceInput registers one device (admin route).
type RegisterDeviceInput struct {
	OwnerID     string                 `json:"ownerId"`
	Name        string                 `json:"name"`
	Kind        string                 `json:"kind,omitempty"`
	HardwareID  string                 `json:"hardwareId,omitempty"`
	Groups      []string               `json:"groups,omitempty"`
	Permissions []Permission           `json:"permissions,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	ExpiresAt   *string                `json:"expiresAt,omitempty"`
	Credential  *CredentialSpec        `json:"credential,omitempty"`
}

// UpdateDeviceInput changes fields on a device. Everything is optional.
type UpdateDeviceInput struct {
	Name        *string                `json:"name,omitempty"`
	Kind        *string                `json:"kind,omitempty"`
	Groups      []string               `json:"groups,omitempty"`
	Permissions []Permission           `json:"permissions,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// DeviceFilters are query parameters for listing devices.
type DeviceFilters struct {
	OwnerID      string
	Status       DeviceStatus
	Group        string
	EnrollmentID string
	Limit        *int
	Offset       *int
}

// DeviceStats are the fleet health counters from GET /devices/stats.
type DeviceStats struct {
	Total        int `json:"total"`
	Active       int `json:"active"`
	Suspended    int `json:"suspended"`
	Revoked      int `json:"revoked"`
	SeenLastHour int `json:"seenLastHour"`
	SeenLastDay  int `json:"seenLastDay"`
	NeverSeen    int `json:"neverSeen"`
}

// EnrollmentTokenInput creates a claim code or a bulk token.
type EnrollmentTokenInput struct {
	OwnerID          string         `json:"ownerId"`
	Kind             EnrollmentKind `json:"kind"`
	MaxUses          *int           `json:"maxUses,omitempty"`
	TTLSeconds       *int           `json:"ttlSeconds,omitempty"`
	Permissions      []Permission   `json:"permissions,omitempty"`
	Groups           []string       `json:"groups,omitempty"`
	DeviceKind       string         `json:"deviceKind,omitempty"`
	DeviceTTLSeconds *int           `json:"deviceTtlSeconds,omitempty"`
}

// EnrollmentToken is a new enrollment token. Token is the plaintext and is
// returned once.
type EnrollmentToken struct {
	ID        string         `json:"id"`
	Kind      EnrollmentKind `json:"kind"`
	Token     string         `json:"token"`
	OwnerID   string         `json:"ownerId"`
	MaxUses   int            `json:"maxUses"`
	ExpiresAt string         `json:"expiresAt"`
}

// EnrollDeviceInput is what a device sends to POST /device/enroll. No other
// credential is needed.
type EnrollDeviceInput struct {
	Token      string         `json:"token"`
	Name       string         `json:"name"`
	Credential CredentialSpec `json:"credential"`
	HardwareID string         `json:"hardwareId,omitempty"`
	// Evidence is attestation evidence, when the server requires it.
	Evidence string `json:"evidence,omitempty"`
	// Nonce is the nonce from AttestationNonce that the evidence is bound to.
	Nonce    string                 `json:"nonce,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// AttestationNonce is a single use nonce to bind into attestation evidence
// (RFC 9334 freshness).
type AttestationNonce struct {
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expiresAt"`
}

// DeviceBundle is a signed offline policy bundle (compact JWS, typ
// device-policy+jwt).
type DeviceBundle struct {
	Token  string                 `json:"token"`
	Claims map[string]interface{} `json:"claims"`
}
