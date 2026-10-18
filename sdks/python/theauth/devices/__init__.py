"""Devices: register, enroll, authorize and revoke IoT devices and robots."""

from theauth.devices.assertion import (
    DEFAULT_AUDIENCE,
    DEVICE_ASSERTION_TYP,
    MAX_LIFETIME_SECONDS,
    DeviceAssertionSigner,
)
from theauth.devices.resource import (
    AsyncDeviceApiResource,
    AsyncDevicesResource,
    DeviceAuth,
    SyncDeviceApiResource,
    SyncDevicesResource,
    device_auth_headers,
)
from theauth.devices.types import (
    AttestationNonce,
    CredentialSpec,
    Device,
    DeviceBundle,
    DeviceCredential,
    DeviceFilters,
    DeviceRegistration,
    DeviceStats,
    EnrollDeviceInput,
    EnrollmentToken,
    EnrollmentTokenInput,
    RegisterDeviceInput,
    UpdateDeviceInput,
)

__all__ = [
    "AsyncDeviceApiResource",
    "AsyncDevicesResource",
    "AttestationNonce",
    "CredentialSpec",
    "DEFAULT_AUDIENCE",
    "DEVICE_ASSERTION_TYP",
    "Device",
    "DeviceAssertionSigner",
    "DeviceAuth",
    "DeviceBundle",
    "DeviceCredential",
    "DeviceFilters",
    "DeviceRegistration",
    "DeviceStats",
    "EnrollDeviceInput",
    "EnrollmentToken",
    "EnrollmentTokenInput",
    "MAX_LIFETIME_SECONDS",
    "RegisterDeviceInput",
    "SyncDeviceApiResource",
    "SyncDevicesResource",
    "UpdateDeviceInput",
    "device_auth_headers",
]
