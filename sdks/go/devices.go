package theauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// DevicesResource is the device registry (admin routes, /devices). It needs a
// user or admin token.
type DevicesResource struct {
	tp *transport
}

// DeviceAPIResource holds the calls a device makes as itself (/device/*).
// Enroll, AttestationNonce and JWKS need no credential.
type DeviceAPIResource struct {
	tp *transport
}

func devicePath(id, suffix string) string {
	return "/devices/" + url.PathEscape(id) + suffix
}

func (tp *transport) doData(ctx context.Context, method, path string, body interface{}, params map[string]string, headers map[string]string, dst interface{}, what string) error {
	var raw json.RawMessage
	if err := tp.doJSONWithHeaders(ctx, method, path, body, params, headers, &raw); err != nil {
		return err
	}
	if dst == nil {
		return nil
	}
	if len(raw) == 0 {
		return fmt.Errorf("theauth: decode %s: empty response", what)
	}
	return decodeData(raw, dst, what)
}

// Register registers a device. A PSK credential's Secret is in the result, once.
func (r *DevicesResource) Register(ctx context.Context, input RegisterDeviceInput) (*DeviceRegistration, error) {
	var out DeviceRegistration
	if err := r.tp.doData(ctx, "POST", "/devices", input, nil, nil, &out, "device registration"); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns devices, optionally filtered.
func (r *DevicesResource) List(ctx context.Context, filters *DeviceFilters) ([]Device, error) {
	var out []Device
	if err := r.tp.doData(ctx, "GET", "/devices", nil, deviceFilterParams(filters), nil, &out, "devices"); err != nil {
		return nil, err
	}
	return out, nil
}

func deviceFilterParams(f *DeviceFilters) map[string]string {
	if f == nil {
		return nil
	}
	p := map[string]string{}
	if f.OwnerID != "" {
		p["ownerId"] = f.OwnerID
	}
	if f.Status != "" {
		p["status"] = string(f.Status)
	}
	if f.Group != "" {
		p["group"] = f.Group
	}
	if f.EnrollmentID != "" {
		p["enrollmentId"] = f.EnrollmentID
	}
	if f.Limit != nil {
		p["limit"] = strconv.Itoa(*f.Limit)
	}
	if f.Offset != nil {
		p["offset"] = strconv.Itoa(*f.Offset)
	}
	return p
}

// Get reads a device. Returns nil, nil when it does not exist.
func (r *DevicesResource) Get(ctx context.Context, id string) (*Device, error) {
	var out Device
	if err := r.tp.doData(ctx, "GET", devicePath(id, ""), nil, nil, nil, &out, "device"); err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return &out, nil
}

// Update changes a device.
func (r *DevicesResource) Update(ctx context.Context, id string, input UpdateDeviceInput) (*Device, error) {
	var out Device
	if err := r.tp.doData(ctx, "PATCH", devicePath(id, ""), input, nil, nil, &out, "device"); err != nil {
		return nil, err
	}
	return &out, nil
}

// Suspend blocks the device until Resume. Its credentials stay valid but are
// refused. Pass an empty reason to give none.
func (r *DevicesResource) Suspend(ctx context.Context, id, reason string) (*Device, error) {
	var body interface{}
	if reason != "" {
		body = map[string]string{"reason": reason}
	}
	var out Device
	if err := r.tp.doData(ctx, "POST", devicePath(id, "/suspend"), body, nil, nil, &out, "device"); err != nil {
		return nil, err
	}
	return &out, nil
}

// Resume lifts a suspension.
func (r *DevicesResource) Resume(ctx context.Context, id string) (*Device, error) {
	var out Device
	if err := r.tp.doData(ctx, "POST", devicePath(id, "/resume"), nil, nil, nil, &out, "device"); err != nil {
		return nil, err
	}
	return &out, nil
}

// Revoke revokes a device for good and returns the ids of the delegations that
// were revoked with it.
func (r *DevicesResource) Revoke(ctx context.Context, id string) ([]string, error) {
	var out struct {
		RevokedDelegations []string `json:"revokedDelegations"`
	}
	if err := r.tp.doData(ctx, "DELETE", devicePath(id, ""), nil, nil, nil, &out, "device revocation"); err != nil {
		return nil, err
	}
	return out.RevokedDelegations, nil
}

// AddCredential adds a credential to a device.
func (r *DevicesResource) AddCredential(ctx context.Context, id string, spec CredentialSpec) (*DeviceCredential, error) {
	var out DeviceCredential
	if err := r.tp.doData(ctx, "POST", devicePath(id, "/credentials"), spec, nil, nil, &out, "device credential"); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeCredential revokes one credential of a device.
func (r *DevicesResource) RevokeCredential(ctx context.Context, id, credentialID string) error {
	return r.tp.doData(ctx, "DELETE", devicePath(id, "/credentials/"+url.PathEscape(credentialID)), nil, nil, nil, nil, "")
}

// IssueBundle issues a signed offline policy bundle for a device (needs
// devices.bundleSigning on the server). Pass nil ttlSeconds for the server default.
func (r *DevicesResource) IssueBundle(ctx context.Context, id string, ttlSeconds *int) (*DeviceBundle, error) {
	var body interface{}
	if ttlSeconds != nil {
		body = map[string]int{"ttlSeconds": *ttlSeconds}
	}
	var out DeviceBundle
	if err := r.tp.doData(ctx, "POST", devicePath(id, "/bundle"), body, nil, nil, &out, "device bundle"); err != nil {
		return nil, err
	}
	return &out, nil
}

// Stats returns fleet health counters. Pass an empty ownerID for all owners you may see.
func (r *DevicesResource) Stats(ctx context.Context, ownerID string) (*DeviceStats, error) {
	var params map[string]string
	if ownerID != "" {
		params = map[string]string{"ownerId": ownerID}
	}
	var out DeviceStats
	if err := r.tp.doData(ctx, "GET", "/devices/stats", nil, params, nil, &out, "device stats"); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateEnrollmentToken creates a claim code or bulk token. The plaintext
// Token is returned once.
func (r *DevicesResource) CreateEnrollmentToken(ctx context.Context, input EnrollmentTokenInput) (*EnrollmentToken, error) {
	var out EnrollmentToken
	if err := r.tp.doData(ctx, "POST", "/devices/enrollment-tokens", input, nil, nil, &out, "enrollment token"); err != nil {
		return nil, err
	}
	return &out, nil
}

// RevokeEnrollmentToken revokes an enrollment token. Devices already enrolled keep working.
func (r *DevicesResource) RevokeEnrollmentToken(ctx context.Context, tokenID string) error {
	return r.tp.doData(ctx, "DELETE", "/devices/enrollment-tokens/"+url.PathEscape(tokenID), nil, nil, nil, nil, "")
}

// Enroll enrolls with a claim code or bulk token and returns a device identity.
func (r *DeviceAPIResource) Enroll(ctx context.Context, input EnrollDeviceInput) (*DeviceRegistration, error) {
	var out DeviceRegistration
	if err := r.tp.doData(ctx, "POST", "/device/enroll", input, nil, nil, &out, "device registration"); err != nil {
		return nil, err
	}
	return &out, nil
}

// AttestationNonce returns a single use nonce to bind into attestation evidence.
func (r *DeviceAPIResource) AttestationNonce(ctx context.Context) (*AttestationNonce, error) {
	var out AttestationNonce
	if err := r.tp.doData(ctx, "POST", "/device/attestation-nonce", nil, nil, nil, &out, "attestation nonce"); err != nil {
		return nil, err
	}
	return &out, nil
}

// Authorize checks an action as the device. A denial, including a bad device
// credential (HTTP 401), is a result with Allowed false and Code set, not an error.
func (r *DeviceAPIResource) Authorize(ctx context.Context, credential DeviceAuth, req AuthorizeRequest) (*AuthorizeResult, error) {
	headers, err := deviceHeaders(credential)
	if err != nil {
		return nil, err
	}
	return r.tp.doDecision(ctx, "/device/authorize", req, headers)
}

// Bundle fetches a fresh offline policy bundle for the calling device.
func (r *DeviceAPIResource) Bundle(ctx context.Context, credential DeviceAuth) (*DeviceBundle, error) {
	headers, err := deviceHeaders(credential)
	if err != nil {
		return nil, err
	}
	var out DeviceBundle
	if err := r.tp.doData(ctx, "GET", "/device/bundle", nil, nil, headers, &out, "device bundle"); err != nil {
		return nil, err
	}
	return &out, nil
}

// JWKS returns the public keys that verify offline policy bundles, as served.
func (r *DeviceAPIResource) JWKS(ctx context.Context) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := r.tp.doJSON(ctx, "GET", "/device/jwks", nil, nil, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func deviceHeaders(credential DeviceAuth) (map[string]string, error) {
	if credential == nil {
		return nil, fmt.Errorf("theauth: a device credential is required")
	}
	value, err := credential.AuthorizationValue()
	if err != nil {
		return nil, err
	}
	return map[string]string{"Authorization": value}, nil
}
