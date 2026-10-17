import type { ButtonHTMLAttributes, ComponentType, InputHTMLAttributes, ReactNode } from "react";

// Class name overrides
// Every component exposes a classNames prop keyed by sub-element name.
// Pass a string to append classes, or a function that receives defaults.

export type ClassNameOverride = string | ((defaultClassName: string) => string);

// Every component exposes a components prop for full slot replacement.

export interface InputSlotProps extends InputHTMLAttributes<HTMLInputElement> {
	label: string;
	error?: string;
}

export interface ButtonSlotProps extends ButtonHTMLAttributes<HTMLButtonElement> {
	loading?: boolean;
	children: ReactNode;
}

export interface LinkSlotProps {
	href: string;
	children: ReactNode;
	className?: string;
	onClick?: () => void;
}

export interface DividerSlotProps {
	label?: string;
	className?: string;
}

export interface ErrorSlotProps {
	message: string;
	className?: string;
}

export interface AvatarSlotProps {
	src?: string;
	name?: string;
	className?: string;
}

export interface SharedSlots {
	Input?: ComponentType<InputSlotProps>;
	Button?: ComponentType<ButtonSlotProps>;
	Link?: ComponentType<LinkSlotProps>;
	Divider?: ComponentType<DividerSlotProps>;
	Error?: ComponentType<ErrorSlotProps>;
}

export interface OAuthProviderMeta {
	id: string;
	name: string;
	icon?: ReactNode;
	color?: string;
}

export interface SignInClassNames {
	root?: ClassNameOverride;
	card?: ClassNameOverride;
	title?: ClassNameOverride;
	form?: ClassNameOverride;
	input?: ClassNameOverride;
	label?: ClassNameOverride;
	button?: ClassNameOverride;
	error?: ClassNameOverride;
	footer?: ClassNameOverride;
	divider?: ClassNameOverride;
	oauthSection?: ClassNameOverride;
	link?: ClassNameOverride;
}

/**
 * What `SignIn` needs from a passkey client. `createPasskeyClient` from
 * `@glinr/theauth-client` satisfies it.
 */
export interface PasskeyClientLike {
	isSupported(): boolean;
	isConditionalAvailable(): Promise<boolean>;
	signIn(options?: {
		conditional?: boolean;
		signal?: AbortSignal;
	}): Promise<{ ok: true } | { ok: false; reason: string; message: string }>;
}

export interface SignInProps {
	classNames?: SignInClassNames;
	/**
	 * Enables passkey sign-in: a button, and autofill suggestions in the email
	 * field when the browser supports conditional UI.
	 */
	passkeyClient?: PasskeyClientLike;
	/** Offer saved passkeys in the email field's autofill. Default true. */
	passkeyAutofill?: boolean;
	components?: SharedSlots;
	providers?: OAuthProviderMeta[];
	basePath?: string;
	onSuccess?: () => void;
	forgotPasswordUrl?: string;
	onForgotPassword?: () => void;
	signUpUrl?: string;
	onSignUp?: () => void;
	showMagicLink?: boolean;
	title?: string;
	footer?: ReactNode;
	disabled?: boolean;
	className?: string;
}

export interface SignUpClassNames {
	root?: ClassNameOverride;
	card?: ClassNameOverride;
	title?: ClassNameOverride;
	form?: ClassNameOverride;
	input?: ClassNameOverride;
	label?: ClassNameOverride;
	button?: ClassNameOverride;
	error?: ClassNameOverride;
	footer?: ClassNameOverride;
	divider?: ClassNameOverride;
	oauthSection?: ClassNameOverride;
	link?: ClassNameOverride;
}

export interface SignUpProps {
	classNames?: SignUpClassNames;
	components?: SharedSlots;
	providers?: OAuthProviderMeta[];
	basePath?: string;
	onSuccess?: () => void;
	signInUrl?: string;
	onSignIn?: () => void;
	showName?: boolean;
	confirmPassword?: boolean;
	title?: string;
	footer?: ReactNode;
	disabled?: boolean;
	className?: string;
}

export interface UserButtonClassNames {
	root?: ClassNameOverride;
	trigger?: ClassNameOverride;
	avatar?: ClassNameOverride;
	dropdown?: ClassNameOverride;
	menuItem?: ClassNameOverride;
	name?: ClassNameOverride;
	email?: ClassNameOverride;
}

export interface UserButtonMenuItem {
	label: string;
	onClick: () => void;
	icon?: ReactNode;
	danger?: boolean;
}

export interface UserButtonProps {
	classNames?: UserButtonClassNames;
	components?: SharedSlots & {
		Avatar?: ComponentType<AvatarSlotProps>;
	};
	menuItems?: UserButtonMenuItem[];
	onSignOut?: () => void;
	showEmail?: boolean;
	className?: string;
}

export interface OAuthButtonsClassNames {
	root?: ClassNameOverride;
	button?: ClassNameOverride;
	icon?: ClassNameOverride;
	label?: ClassNameOverride;
}

export interface OAuthButtonsProps {
	classNames?: OAuthButtonsClassNames;
	components?: {
		Button?: ComponentType<ButtonSlotProps>;
	};
	providers: OAuthProviderMeta[];
	basePath?: string;
	mode?: "signin" | "signup";
	layout?: "grid" | "list";
	disabled?: boolean;
	className?: string;
}

export interface ForgotPasswordClassNames {
	root?: ClassNameOverride;
	card?: ClassNameOverride;
	title?: ClassNameOverride;
	form?: ClassNameOverride;
	input?: ClassNameOverride;
	button?: ClassNameOverride;
	error?: ClassNameOverride;
	success?: ClassNameOverride;
	link?: ClassNameOverride;
}

export interface ForgotPasswordProps {
	classNames?: ForgotPasswordClassNames;
	components?: SharedSlots;
	basePath?: string;
	onSuccess?: () => void;
	signInUrl?: string;
	onSignIn?: () => void;
	title?: string;
	className?: string;
}

export interface TwoFactorClassNames {
	root?: ClassNameOverride;
	card?: ClassNameOverride;
	title?: ClassNameOverride;
	description?: ClassNameOverride;
	form?: ClassNameOverride;
	input?: ClassNameOverride;
	button?: ClassNameOverride;
	error?: ClassNameOverride;
	backupLink?: ClassNameOverride;
}

export interface TwoFactorVerifyProps {
	classNames?: TwoFactorClassNames;
	components?: SharedSlots;
	basePath?: string;
	onSuccess?: () => void;
	onCancel?: () => void;
	digits?: number;
	showBackupOption?: boolean;
	title?: string;
	className?: string;
}

export interface AuthCardClassNames {
	root?: ClassNameOverride;
	card?: ClassNameOverride;
	title?: ClassNameOverride;
	description?: ClassNameOverride;
}

export interface AuthCardProps {
	classNames?: AuthCardClassNames;
	title?: string;
	description?: string;
	children: ReactNode;
	className?: string;
}
