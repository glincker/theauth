import type { ButtonHTMLAttributes, ComponentType, InputHTMLAttributes, ReactNode } from "react";

// Class name overrides
// Every component exposes a classNames prop keyed by sub-element name.
// Pass a string to append classes, or a function that receives defaults.

export type ClassNameOverride = string | ((defaultClassName: string) => string);

// Slot replacement
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

// Shared component slots

export interface SharedSlots {
	Input?: ComponentType<InputSlotProps>;
	Button?: ComponentType<ButtonSlotProps>;
	Link?: ComponentType<LinkSlotProps>;
	Divider?: ComponentType<DividerSlotProps>;
	Error?: ComponentType<ErrorSlotProps>;
}

// OAuth provider metadata

export interface OAuthProviderMeta {
	id: string;
	name: string;
	icon?: ReactNode;
	color?: string;
}

// Sign-in component

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

export interface SignInProps {
	classNames?: SignInClassNames;
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

// Sign-up component

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

// User button

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

// OAuth buttons

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

// Forgot password

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

// Two-factor verify

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

// Auth card

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
