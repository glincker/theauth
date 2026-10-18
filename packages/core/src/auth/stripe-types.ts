export interface StripeConfig {
	/** Stripe secret key (sk_live_... or sk_test_...) */
	secretKey: string;
	/** Stripe webhook signing secret (whsec_...) */
	webhookSecret: string;
	/** Auto-create a Stripe customer when the user record is referenced (default: true) */
	autoCreateCustomer?: boolean;
	/** Stripe API version (default: "2024-12-18.acacia") */
	apiVersion?: string;
	/** Callback fired whenever subscription data changes for a user */
	onSubscriptionChange?: (userId: string, subscription: SubscriptionInfo) => Promise<void>;
}

export interface SubscriptionInfo {
	id: string;
	status: "active" | "canceled" | "past_due" | "trialing" | "unpaid" | "incomplete";
	priceId: string;
	currentPeriodEnd: Date;
	cancelAtPeriodEnd: boolean;
}

export interface CheckoutOptions {
	successUrl?: string;
	cancelUrl?: string;
	trialDays?: number;
	metadata?: Record<string, string>;
}

export interface StripeModule {
	/** Create a Stripe customer for a user and persist the customer ID */
	createCustomer(userId: string, email: string, name?: string): Promise<string>;
	/** Get the Stripe customer ID stored for a user */
	getCustomerId(userId: string): Promise<string | null>;
	/** Create a Stripe Checkout Session and return its URL + ID */
	createCheckoutSession(
		userId: string,
		priceId: string,
		options?: CheckoutOptions,
	): Promise<{ url: string; sessionId: string }>;
	/** Create a Stripe Billing Portal session and return its URL */
	createPortalSession(userId: string, returnUrl: string): Promise<{ url: string }>;
	/** Return current subscription info for a user from the database */
	getSubscription(userId: string): Promise<SubscriptionInfo | null>;
	/** Verify Stripe webhook signature and dispatch to internal handlers */
	handleWebhook(request: Request): Promise<Response>;
	/** Route an incoming HTTP request to the appropriate handler (returns null if path unmatched) */
	handleRequest(request: Request): Promise<Response | null>;
}

// Internal Stripe REST types (minimal, only fields we use)

export interface StripeCustomer {
	id: string;
	email: string | null;
	name: string | null;
}

export interface StripeCheckoutSession {
	id: string;
	url: string | null;
	customer: string | null;
	subscription: string | null;
}

export interface StripeBillingPortalSession {
	url: string;
}

export interface StripeSubscription {
	id: string;
	status: string;
	customer: string;
	cancel_at_period_end: boolean;
	current_period_end: number;
	items: {
		data: Array<{ price: { id: string } }>;
	};
}

export interface StripeInvoice {
	id: string;
	customer: string;
	subscription: string | null;
}

export interface StripeEvent {
	id: string;
	type: string;
	data: { object: Record<string, unknown> };
}

// Stripe REST API client helpers
