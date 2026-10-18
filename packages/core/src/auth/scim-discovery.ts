import {
	getBaseUrl,
	SCHEMA_ENTERPRISE,
	SCHEMA_ERROR,
	SCHEMA_GROUP,
	SCHEMA_LIST,
	SCHEMA_RESOURCE_TYPE,
	SCHEMA_SP_CONFIG,
	SCHEMA_USER,
	SCIM_CONTENT_TYPE,
	scimError,
	scimResponse,
} from "./scim-helpers.js";

export function handleServiceProviderConfig(request: Request): Response {
	const baseUrl = getBaseUrl(request);
	return scimResponse({
		schemas: [SCHEMA_SP_CONFIG],
		documentationUri: "https://theauth.dev/docs/scim",
		patch: { supported: true },
		bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
		filter: { supported: true, maxResults: 200 },
		changePassword: { supported: false },
		sort: { supported: true },
		etag: { supported: false },
		authenticationSchemes: [
			{
				type: "oauthbearertoken",
				name: "OAuth Bearer Token",
				description: "Authentication scheme using OAuth Bearer Token",
				specUri: "https://www.rfc-editor.org/rfc/rfc6750",
				primary: true,
			},
		],
		meta: {
			resourceType: "ServiceProviderConfig",
			location: `${baseUrl}/scim/v2/ServiceProviderConfig`,
		},
	});
}

export function handleSchemas(request: Request): Response {
	const baseUrl = getBaseUrl(request);
	return scimResponse({
		schemas: [SCHEMA_LIST],
		totalResults: 3,
		startIndex: 1,
		itemsPerPage: 3,
		Resources: [
			{
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
				id: SCHEMA_USER,
				name: "User",
				description: "User Account",
				attributes: [
					{ name: "userName", type: "string", required: true, uniqueness: "server" },
					{ name: "displayName", type: "string", required: false },
					{
						name: "name",
						type: "complex",
						required: false,
						subAttributes: [
							{ name: "givenName", type: "string" },
							{ name: "familyName", type: "string" },
							{ name: "formatted", type: "string" },
						],
					},
					{ name: "emails", type: "complex", multiValued: true, required: false },
					{ name: "active", type: "boolean", required: false },
					{ name: "externalId", type: "string", required: false },
				],
				meta: {
					resourceType: "Schema",
					location: `${baseUrl}/scim/v2/Schemas/${SCHEMA_USER}`,
				},
			},
			{
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
				id: SCHEMA_GROUP,
				name: "Group",
				description: "Group",
				attributes: [
					{ name: "displayName", type: "string", required: true },
					{ name: "members", type: "complex", multiValued: true, required: false },
					{ name: "externalId", type: "string", required: false },
				],
				meta: {
					resourceType: "Schema",
					location: `${baseUrl}/scim/v2/Schemas/${SCHEMA_GROUP}`,
				},
			},
			{
				schemas: ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
				id: SCHEMA_ENTERPRISE,
				name: "EnterpriseUser",
				description:
					"Enterprise User extension (RFC 7643 §4.3). Carries employeeNumber, department, and manager.",
				attributes: [
					{
						name: "employeeNumber",
						type: "string",
						required: false,
						mutability: "readWrite",
					},
					{ name: "department", type: "string", required: false, mutability: "readWrite" },
					{ name: "costCenter", type: "string", required: false, mutability: "readWrite" },
					{ name: "organization", type: "string", required: false, mutability: "readWrite" },
					{ name: "division", type: "string", required: false, mutability: "readWrite" },
					{
						name: "manager",
						type: "complex",
						required: false,
						mutability: "readWrite",
						subAttributes: [
							{ name: "value", type: "string" },
							{ name: "$ref", type: "reference" },
							{ name: "displayName", type: "string" },
						],
					},
				],
				meta: {
					resourceType: "Schema",
					location: `${baseUrl}/scim/v2/Schemas/${SCHEMA_ENTERPRISE}`,
				},
			},
		],
	});
}

export function handleResourceTypes(request: Request): Response {
	const baseUrl = getBaseUrl(request);
	return scimResponse({
		schemas: [SCHEMA_LIST],
		totalResults: 2,
		startIndex: 1,
		itemsPerPage: 2,
		Resources: [
			{
				schemas: [SCHEMA_RESOURCE_TYPE],
				id: "User",
				name: "User",
				endpoint: "/Users",
				description: "User Account",
				schema: SCHEMA_USER,
				meta: {
					resourceType: "ResourceType",
					location: `${baseUrl}/scim/v2/ResourceTypes/User`,
				},
			},
			{
				schemas: [SCHEMA_RESOURCE_TYPE],
				id: "Group",
				name: "Group",
				endpoint: "/Groups",
				description: "Group",
				schema: SCHEMA_GROUP,
				meta: {
					resourceType: "ResourceType",
					location: `${baseUrl}/scim/v2/ResourceTypes/Group`,
				},
			},
		],
	});
}

// /Bulk (RFC 7644 §3.7). Advertised as unsupported, but routed so probes get a spec-correct 501.

const SCHEMA_BULK_REQUEST = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";

export function handleBulk(request: Request): Response {
	const contentType = request.headers.get("Content-Type") ?? "";
	if (!contentType.toLowerCase().startsWith(SCIM_CONTENT_TYPE)) {
		return scimError(`Bulk requires Content-Type "${SCIM_CONTENT_TYPE}"`, 415, "invalidValue");
	}

	// The body is never parsed: bulk is unsupported, and the same error is returned for every body.
	return scimResponse(
		{
			schemas: [SCHEMA_ERROR],
			status: "501",
			detail: `Bulk operations are not supported by this server. See /scim/v2/ServiceProviderConfig for supported features. Requested schema: ${SCHEMA_BULK_REQUEST}`,
		},
		501,
	);
}
