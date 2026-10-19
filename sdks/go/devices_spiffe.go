package theauth

import (
	"context"
	"errors"
)

// SPIFFEPresentation is an SVID handed to an admin route: an X.509 chain (PEM,
// leaf first) or a compact JWT-SVID. Build one with SPIFFEX509 or SPIFFEJWT.
type SPIFFEPresentation struct {
	Kind  string `json:"kind"`
	Chain string `json:"chain,omitempty"`
	Token string `json:"token,omitempty"`
}

// SPIFFEX509 presents an X.509-SVID chain, leaf first.
func SPIFFEX509(chainPEM string) SPIFFEPresentation {
	return SPIFFEPresentation{Kind: "x509", Chain: chainPEM}
}

// SPIFFEJWT presents a compact JWT-SVID.
func SPIFFEJWT(token string) SPIFFEPresentation {
	return SPIFFEPresentation{Kind: "jwt", Token: token}
}

// SPIFFESvid describes the verified SVID.
type SPIFFESvid struct {
	Kind       string `json:"kind"`
	ExpiresAt  string `json:"expiresAt"`
	Thumbprint string `json:"thumbprint,omitempty"`
}

// SPIFFEPrincipal is the device or agent an SVID maps to.
type SPIFFEPrincipal struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// SPIFFEVerifyResult is the answer of a SPIFFE verification. Code is "ok" or a
// failure code such as "expired" or "unknown_workload".
type SPIFFEVerifyResult struct {
	OK        bool             `json:"ok"`
	Code      string           `json:"code"`
	Reason    string           `json:"reason,omitempty"`
	SpiffeID  string           `json:"spiffeId,omitempty"`
	Svid      *SPIFFESvid      `json:"svid,omitempty"`
	Principal *SPIFFEPrincipal `json:"principal,omitempty"`
}

// SPIFFEIssuedToken is an agent token bound to an X.509-SVID (RFC 8705). Token
// is returned once.
type SPIFFEIssuedToken struct {
	AgentID string            `json:"agentId"`
	Token   string            `json:"token"`
	CNF     map[string]string `json:"cnf"`
}

// SPIFFEVerify checks an SVID against the trust bundles. It mints nothing. A
// mapping owned by someone else reads as unmapped.
func (r *DevicesResource) SPIFFEVerify(ctx context.Context, presentation SPIFFEPresentation) (*SPIFFEVerifyResult, error) {
	var out SPIFFEVerifyResult
	if err := r.tp.doData(ctx, "POST", "/devices/spiffe/verify", presentation, nil, nil, &out, "spiffe verification"); err != nil {
		return nil, err
	}
	return &out, nil
}

// SPIFFEToken issues an agent token bound to an X.509-SVID. It rotates the
// agent token and works for agent workloads only.
func (r *DevicesResource) SPIFFEToken(ctx context.Context, chainPEM string) (*SPIFFEIssuedToken, error) {
	var out SPIFFEIssuedToken
	body := map[string]string{"chain": chainPEM}
	if err := r.tp.doData(ctx, "POST", "/devices/spiffe/token", body, nil, nil, &out, "spiffe token"); err != nil {
		return nil, err
	}
	return &out, nil
}

// LinkSPIFFEID links a SPIFFE ID in a configured trust domain to a device.
func (r *DevicesResource) LinkSPIFFEID(ctx context.Context, deviceID, spiffeID string) (*DeviceCredential, error) {
	if spiffeID == "" {
		return nil, errors.New("theauth: a SPIFFE ID is required")
	}
	return r.linkSPIFFE(ctx, deviceID, map[string]interface{}{"spiffeId": spiffeID})
}

// LinkSPIFFEPresentation links the SPIFFE ID of a verified SVID to a device.
func (r *DevicesResource) LinkSPIFFEPresentation(ctx context.Context, deviceID string, presentation SPIFFEPresentation) (*DeviceCredential, error) {
	return r.linkSPIFFE(ctx, deviceID, map[string]interface{}{"presentation": presentation})
}

func (r *DevicesResource) linkSPIFFE(ctx context.Context, deviceID string, body map[string]interface{}) (*DeviceCredential, error) {
	var out DeviceCredential
	if err := r.tp.doData(ctx, "POST", devicePath(deviceID, "/spiffe"), body, nil, nil, &out, "device credential"); err != nil {
		return nil, err
	}
	return &out, nil
}

// SPIFFEVerify verifies the device's own JWT-SVID. A refused SVID returns an
// *ErrAuthentication whose Code is the failure code. An X.509-SVID cannot be
// sent here: the server reads it from the TLS handshake or a trusted proxy header.
func (r *DeviceAPIResource) SPIFFEVerify(ctx context.Context, jwtSVID string) (*SPIFFEVerifyResult, error) {
	if jwtSVID == "" {
		return nil, errors.New("theauth: a JWT-SVID is required")
	}
	var out SPIFFEVerifyResult
	headers := map[string]string{"Authorization": "Bearer " + jwtSVID}
	if err := r.tp.doData(ctx, "POST", "/device/spiffe/verify", nil, nil, headers, &out, "spiffe verification"); err != nil {
		return nil, err
	}
	return &out, nil
}
