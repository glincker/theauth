export { AuthCard } from "./components/auth-card.js";
export { ForgotPassword } from "./components/forgot-password.js";
export { OAuthButtons } from "./components/oauth-buttons.js";
export { SignIn } from "./components/sign-in.js";
export { SignUp } from "./components/sign-up.js";
export { TwoFactorVerify } from "./components/two-factor-verify.js";
export { UserButton } from "./components/user-button.js";

// OAuth provider metadata + icons (users can use these or bring their own)
export {
	AppleIcon,
	DiscordIcon,
	FacebookIcon,
	GitHubIcon,
	GitLabIcon,
	GoogleIcon,
	LinkedInIcon,
	MicrosoftIcon,
	NotionIcon,
	OAUTH_PROVIDERS,
	RedditIcon,
	SlackIcon,
	SpotifyIcon,
	TwitchIcon,
	TwitterIcon,
} from "./icons/oauth-icons.js";
export type {
	AuthCardClassNames,
	AuthCardProps,
	AvatarSlotProps,
	ButtonSlotProps,
	ClassNameOverride,
	DividerSlotProps,
	ErrorSlotProps,
	ForgotPasswordClassNames,
	ForgotPasswordProps,
	// Slot props (for building custom components that plug into our slots)
	InputSlotProps,
	LinkSlotProps,
	OAuthButtonsClassNames,
	OAuthButtonsProps,
	OAuthProviderMeta,
	PasskeyClientLike,
	SharedSlots,
	SignInClassNames,
	SignInProps,
	SignUpClassNames,
	SignUpProps,
	TwoFactorClassNames,
	TwoFactorVerifyProps,
	UserButtonClassNames,
	UserButtonMenuItem,
	UserButtonProps,
} from "./types.js";
// Utility for class merging (users may want this for their own components)
export { cx } from "./utils.js";
