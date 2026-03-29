"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu, X, Moon, Sun, ArrowRight, ChevronDown } from "lucide-react";
import { useTheme } from "next-themes";
import { useState, useEffect, useRef } from "react";
import posthog from "posthog-js";
import { Logo } from "./logo";

const PRODUCT_LINKS = [
	{ href: "/products/agent-identity", label: "Agent identity", description: "Cryptographic tokens, permissions, delegation, audit" },
	{ href: "/products/security", label: "Security", description: "Anomaly detection, trust scoring, compliance" },
	{ href: "/products/platform", label: "Platform", description: "MCP OAuth 2.1, adapters, dashboard, SDK" },
] as const;

function GitHubIcon({ className }: { className?: string }) {
	return (
		<svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
			<path d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.17 6.839 9.49.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.167 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
		</svg>
	);
}

function NpmIcon({ className }: { className?: string }) {
	return (
		<svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
			<path d="M0 7.334v8h6.666v1.332H12v-1.332h12v-8H0zm6.666 6.664H5.334v-4H3.999v4H1.335V8.667h5.331v5.331zm4 0v1.336H8.001V8.667h5.334v5.332h-2.669v-.001zm12.001 0h-1.33v-4h-1.336v4h-1.335v-4h-1.33v4h-2.671V8.667h8.002v5.331zM10.665 10H12v2.667h-1.335V10z" />
		</svg>
	);
}

export function Nav() {
	const pathname = usePathname();
	const { resolvedTheme, setTheme } = useTheme();
	const [mobileOpen, setMobileOpen] = useState(false);
	const [productsOpen, setProductsOpen] = useState(false);
	const [mounted, setMounted] = useState(false);
	const productsRef = useRef<HTMLDivElement>(null);
	const isDocsPage = pathname.startsWith("/docs");
	const isHome = pathname === "/";
	const isProductsPage = pathname.startsWith("/products");

	useEffect(() => { setMounted(true); }, []);
	useEffect(() => { setMobileOpen(false); setProductsOpen(false); }, [pathname]);
	useEffect(() => {
		function handleClickOutside(e: MouseEvent) {
			if (productsRef.current && !productsRef.current.contains(e.target as Node)) setProductsOpen(false);
		}
		document.addEventListener("mousedown", handleClickOutside);
		return () => document.removeEventListener("mousedown", handleClickOutside);
	}, []);

	return (
		<>
			<header className="glass-nav fixed top-0 z-50 w-full border-b border-neutral-200/30 bg-white/80 backdrop-blur-2xl dark:border-[var(--kavach-border-ghost)]">
				<div className="relative mx-auto flex h-[var(--nav-height)] max-w-[1400px] items-center justify-between px-5 lg:px-8">

					{/* Left: Logo */}
					<Link href="/" className="group flex items-center gap-3 rounded-xl px-2 py-2 transition-all hover:bg-fd-accent/40">
						<Logo size={30} />
						<div className="flex items-baseline gap-[2px] font-heading text-[17px] font-bold tracking-tight">
							<span>kavach</span>
							<span className="text-[13px] font-extralight tracking-wider text-fd-muted-foreground/40">OS</span>
						</div>
					</Link>

					{/* Center: Nav links (absolute center) */}
					<nav className="absolute left-1/2 top-1/2 hidden -translate-x-1/2 -translate-y-1/2 items-center gap-1 md:flex">
						{/* Products dropdown */}
						<div ref={productsRef} className="relative">
							<button
								type="button"
								onClick={() => {
									const next = !productsOpen;
									setProductsOpen(next);
									if (next) posthog.capture("products_menu_opened");
								}}
								className={`flex h-[var(--nav-height)] items-center gap-1 border-b-2 px-4 text-[13px] font-medium transition-all ${
									isProductsPage || productsOpen
										? "border-fd-foreground text-fd-foreground"
										: "border-transparent text-fd-muted-foreground hover:text-fd-foreground hover:border-fd-muted-foreground/20"
								}`}
							>
								Products
								<ChevronDown className={`h-3 w-3 opacity-50 transition-transform duration-200 ${productsOpen ? "rotate-180" : ""}`} />
							</button>
							{productsOpen && (
								<div className="gold-glow absolute left-1/2 top-full mt-2 w-80 -translate-x-1/2 overflow-hidden rounded-2xl border border-[var(--kavach-border-ghost)] bg-[var(--kavach-surface-high)] p-1.5 shadow-2xl shadow-black/30 backdrop-blur-xl dark:bg-[var(--kavach-surface-high)]">
									{PRODUCT_LINKS.map((link) => (
										<Link
											key={link.href}
											href={link.href}
											onClick={() => posthog.capture("product_page_clicked", { product: link.label, href: link.href })}
											className="flex flex-col gap-0.5 rounded-xl px-4 py-3 transition-colors hover:bg-[var(--kavach-surface-bright)]"
										>
											<span className="text-sm font-medium text-[var(--kavach-text)]">{link.label}</span>
											<span className="text-[11px] text-[var(--kavach-text-muted)]">{link.description}</span>
										</Link>
									))}
								</div>
							)}
						</div>

						<NavLink href="/docs" active={isDocsPage}>Docs</NavLink>

						<Link
							href="/docs/quickstart"
							className="flex h-[var(--nav-height)] items-center border-b-2 border-transparent px-4 text-[13px] font-medium text-fd-muted-foreground transition-all hover:text-fd-foreground hover:border-fd-muted-foreground/20"
						>
							Quickstart
						</Link>
					</nav>

					{/* Right: Icons + CTA */}
					<div className="flex items-center gap-0.5">
						<Link
							href="https://github.com/kavachos/kavachos"
							target="_blank"
							rel="noopener noreferrer"
							onClick={() => posthog.capture("github_link_clicked")}
							className="rounded-lg p-2.5 text-fd-muted-foreground/60 transition-all hover:bg-fd-accent/40 hover:text-fd-foreground"
							aria-label="GitHub"
						>
							<GitHubIcon className="h-5 w-5" />
						</Link>
						<Link
							href="https://www.npmjs.com/package/kavachos"
							target="_blank"
							rel="noopener noreferrer"
							onClick={() => posthog.capture("npm_link_clicked")}
							className="rounded-lg p-2.5 text-fd-muted-foreground/60 transition-all hover:bg-fd-accent/40 hover:text-fd-foreground"
							aria-label="npm"
						>
							<NpmIcon className="h-5 w-5" />
						</Link>

						{mounted && (
							<button
								type="button"
								onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
								className="rounded-lg p-2.5 text-fd-muted-foreground/60 transition-all hover:bg-fd-accent/40 hover:text-fd-foreground"
								aria-label="Toggle theme"
							>
								{resolvedTheme === "dark" ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
							</button>
						)}

						<div className="mx-2 hidden h-5 w-px bg-fd-border/40 sm:block" />

						{/* CTA with shine effect */}
						<Link
							href="/docs/quickstart"
							onClick={() => posthog.capture("get_started_clicked", { location: "nav_desktop" })}
							className="btn-gold-gradient nav-cta-shine group relative hidden items-center gap-1.5 overflow-hidden rounded-full px-5 py-2 text-[13px] font-semibold text-[#3D2E00] transition-all hover:shadow-lg hover:shadow-[var(--kavach-glow)] sm:inline-flex"
						>
							Get started
							<ArrowRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
						</Link>

						{/* Mobile menu */}
						<button
							type="button"
							onClick={() => setMobileOpen(!mobileOpen)}
							className="rounded-lg p-2.5 text-fd-muted-foreground/60 transition-all hover:bg-fd-accent/40 md:hidden"
							aria-label="Toggle menu"
						>
							{mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
						</button>
					</div>
				</div>
			</header>

			{/* Mobile menu */}
			{mobileOpen && (
				<div className="fixed inset-0 top-[var(--nav-height)] z-40 overflow-y-auto border-t border-fd-border bg-fd-background/95 backdrop-blur-xl md:hidden">
					<nav className="mx-auto flex max-w-sm flex-col gap-1 p-6">
						<MobileNavLink href="/" active={isHome}>Home</MobileNavLink>
						<MobileNavLink href="/docs" active={isDocsPage}>Documentation</MobileNavLink>
						<p className="mt-3 px-4 text-[10px] font-semibold uppercase tracking-[0.12em] text-fd-muted-foreground/40">Products</p>
						{PRODUCT_LINKS.map((link) => (
							<MobileNavLink key={link.href} href={link.href} active={pathname === link.href}>{link.label}</MobileNavLink>
						))}
						<MobileNavLink href="https://github.com/kavachos/kavachos" external>GitHub</MobileNavLink>
						<div className="mt-6 border-t border-fd-border pt-6">
							<Link href="/docs/quickstart" onClick={() => posthog.capture("get_started_clicked", { location: "nav_mobile" })} className="kavach-btn-gold relative flex items-center justify-center gap-2 overflow-hidden rounded-full px-4 py-3 text-sm font-semibold text-[#1a1000]">
								Get started <ArrowRight className="h-4 w-4" />
							</Link>
						</div>
					</nav>
				</div>
			)}
		</>
	);
}

export function NavSpacer() {
	return <div className="h-[var(--nav-height)]" />;
}

function NavLink({ href, active, children }: { href: string; active?: boolean; children: React.ReactNode }) {
	return (
		<Link
			href={href}
			className={`flex h-[var(--nav-height)] items-center border-b-2 px-4 text-[13px] font-medium transition-all ${
				active
					? "border-fd-foreground text-fd-foreground"
					: "border-transparent text-fd-muted-foreground hover:text-fd-foreground hover:border-fd-muted-foreground/20"
			}`}
		>
			{children}
		</Link>
	);
}

function MobileNavLink({ href, active, external, children }: { href: string; active?: boolean; external?: boolean; children: React.ReactNode }) {
	return (
		<Link
			href={href}
			className={`rounded-xl px-4 py-3 text-sm transition-colors ${
				active ? "bg-fd-accent/50 font-medium text-fd-foreground" : "text-fd-muted-foreground/70 hover:bg-fd-accent/50 hover:text-fd-foreground"
			}`}
			{...(external ? { target: "_blank", rel: "noopener noreferrer" } : {})}
		>
			{children}
		</Link>
	);
}
