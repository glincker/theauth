#!/usr/bin/env node
// Builds the branded isometric docs diagrams. Run: node scripts/build-diagrams.mjs
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "docs", "images", "shared-signals");
const C = {
	bg: "#06080a",
	top: "#1b2329",
	left: "#10171b",
	right: "#0b1115",
	edge: "#2a3a42",
	teal: "#19d9b8",
	lime: "#eef35f",
	purple: "#8b7cf6",
	text: "#f4f4f5",
	muted: "#9ca3af",
};
const FONT = "Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif";
const MONO = "ui-monospace,JetBrains Mono,Menlo,Consolas,monospace";
const f = (n) => Math.round(n * 10) / 10;
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");

function scene(w, h, X, Y) {
	const top = 110;
	const u = Math.min((w - 48) / ((X + Y) * 0.866), (h - top - 24) / ((X + Y) * 0.5));
	const ox = w / 2 + ((Y - X) / 2) * 0.866 * u;
	const oy = top;
	const P = (x, y, z = 0) => [f(ox + (x - y) * 0.866 * u), f(oy + (x + y) * 0.5 * u - z * u)];
	const pts = (arr) => arr.map((p) => p.join(",")).join(" ");
	const poly = (arr, fill, stroke = C.edge) =>
		`<polygon points="${pts(arr)}" fill="${fill}" stroke="${stroke}" stroke-width="1" stroke-linejoin="round"/>`;
	const out = [];

	function platform(x1, y1, x2, y2) {
		const h0 = 0.35;
		out.push(poly([P(x1, y2, 0), P(x2, y2, 0), P(x2, y2, h0), P(x1, y2, h0)], C.left));
		out.push(poly([P(x2, y1, 0), P(x2, y2, 0), P(x2, y2, h0), P(x2, y1, h0)], C.right));
		out.push(poly([P(x1, y1, h0), P(x2, y1, h0), P(x2, y2, h0), P(x1, y2, h0)], "#12191d"));
		for (let gx = x1 + 1; gx < x2; gx += 1)
			for (let gy = y1 + 1; gy < y2; gy += 1) {
				const [px, py] = P(gx, gy, h0);
				out.push(`<circle cx="${px}" cy="${py}" r="1" fill="#3b4b53" opacity=".55"/>`);
			}
		out.push(`<g data-base="${h0}"></g>`);
		return h0;
	}

	function cuboid(x, y, w, d, hh, { accent = C.teal, base = 0.35, inset = true } = {}) {
		const z0 = base;
		const z1 = base + hh;
		out.push(
			poly([P(x, y + d, z0), P(x + w, y + d, z0), P(x + w, y + d, z1), P(x, y + d, z1)], C.left),
		);
		out.push(
			poly([P(x + w, y, z0), P(x + w, y + d, z0), P(x + w, y + d, z1), P(x + w, y, z1)], C.right),
		);
		out.push(poly([P(x, y, z1), P(x + w, y, z1), P(x + w, y + d, z1), P(x, y + d, z1)], C.top));
		if (inset) {
			const m = Math.min(w, d) * 0.28;
			out.push(
				`<polygon points="${pts([P(x + m, y + m, z1), P(x + w - m, y + m, z1), P(x + w - m, y + d - m, z1), P(x + m, y + d - m, z1)])}" fill="${accent}" fill-opacity=".14" stroke="${accent}" stroke-width="2" stroke-linejoin="round"/>`,
			);
		}
		// glowing base edge
		const a = P(x, y + d, z0 + 0.12);
		const b = P(x + w, y + d, z0 + 0.12);
		const c = P(x + w, y, z0 + 0.12);
		out.push(
			`<polyline points="${pts([a, b, c])}" fill="none" stroke="${accent}" stroke-width="1.6" opacity=".9"/>`,
		);
		return { top: P(x + w / 2, y + d / 2, z1), cx: x + w / 2, cy: y + d / 2, z1 };
	}

	function route(path, color = C.teal, z = 0.4, arrow = true) {
		const s = path.map(([x, y]) => P(x, y, z));
		out.push(
			`<polyline points="${pts(s)}" fill="none" stroke="${color}" stroke-width="2" stroke-dasharray="1 7" stroke-linecap="round" stroke-linejoin="round"/>`,
		);
		const [ex, ey] = s[s.length - 1];
		out.push(`<circle cx="${ex}" cy="${ey}" r="4" fill="${color}"/>`);
		if (arrow) {
			const [sx, sy] = s[0];
			out.push(`<circle cx="${sx}" cy="${sy}" r="3" fill="${color}" opacity=".7"/>`);
		}
	}

	function tag([x, y], label, lift = 34) {
		const w = Math.max(64, label.length * 7.6 + 24);
		const ty = y - lift;
		out.push(
			`<line x1="${x}" y1="${ty + 13}" x2="${x}" y2="${y}" stroke="${C.teal}" stroke-width="1.5"/><circle cx="${x}" cy="${y}" r="3" fill="${C.teal}"/>`,
			`<rect x="${f(x - w / 2)}" y="${ty - 13}" width="${f(w)}" height="26" rx="13" fill="#0b1013" stroke="#34464e"/>`,
			`<text x="${x}" y="${ty + 4.5}" text-anchor="middle" font-size="13" fill="${C.text}" font-family="${MONO}">${esc(label)}</text>`,
		);
	}

	function badge([x, y], n) {
		out.push(
			`<text x="${x}" y="${y + 6}" text-anchor="middle" font-size="18" font-weight="700" fill="${C.lime}">${n}</text>`,
		);
	}

	return { P, out, platform, cuboid, route, tag, badge, w, h };
}

function wrap(s, title, desc) {
	const { w, h } = s;
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" role="img" aria-labelledby="t d" font-family="${FONT}">
<title id="t">${esc(title)}</title><desc id="d">${esc(desc)}</desc>
<defs>
<radialGradient id="g1" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(0 0) scale(${w * 0.5} ${h * 0.8})"><stop stop-color="${C.teal}" stop-opacity=".30"/><stop offset="1" stop-color="${C.teal}" stop-opacity="0"/></radialGradient>
<radialGradient id="g2" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(${w * 0.5} 0) scale(${w * 0.35} ${h * 0.6})"><stop stop-color="${C.purple}" stop-opacity=".22"/><stop offset="1" stop-color="${C.purple}" stop-opacity="0"/></radialGradient>
<radialGradient id="g3" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(${w} 0) scale(${w * 0.45} ${h * 0.8})"><stop stop-color="${C.lime}" stop-opacity=".22"/><stop offset="1" stop-color="${C.lime}" stop-opacity="0"/></radialGradient>
<filter id="n" x="0" y="0" width="100%" height="100%"><feTurbulence type="fractalNoise" baseFrequency=".85" numOctaves="2" seed="11" stitchTiles="stitch"/><feColorMatrix values="0 0 0 0 1  0 0 0 0 1  0 0 0 0 1  0 0 0 .7 0"/></filter>
</defs>
<rect width="${w}" height="${h}" rx="16" fill="${C.bg}"/>
<rect width="${w}" height="${h}" rx="16" fill="url(#g1)"/><rect width="${w}" height="${h}" rx="16" fill="url(#g2)"/><rect width="${w}" height="${h}" rx="16" fill="url(#g3)"/>
<rect width="${w}" height="${h}" rx="16" filter="url(#n)" opacity=".10"/>
${s.out.join("\n")}
<g transform="translate(24 22)"><rect x=".75" y=".75" width="26.5" height="26.5" rx="7.5" fill="none" stroke="${C.purple}" stroke-width="2"/><rect x="7" y="7" width="14" height="14" rx="4" fill="none" stroke="${C.purple}" stroke-width="1.6"/><rect x="11" y="11" width="6" height="6" rx="1.8" fill="${C.lime}"/><text x="38" y="20" font-size="17" font-weight="600" fill="${C.text}">theAuth</text></g>
</svg>
`;
}

// 1. overview: transmitter -> signed event -> two receivers
{
	const s = scene(720, 420, 12, 6);
	s.platform(0, 0, 12, 6);
	const tx = s.cuboid(1, 2, 2, 2, 1.4, { accent: C.purple });
	const set = s.cuboid(5, 2.3, 1.4, 1.4, 0.5, { accent: C.lime });
	const ra = s.cuboid(8.6, 0.4, 2, 1.8, 2, { accent: C.teal });
	const rb = s.cuboid(8.6, 3.8, 2, 1.8, 1.2, { accent: C.teal });
	s.route(
		[
			[3.2, 3],
			[5, 3],
		],
		C.lime,
	);
	s.route(
		[
			[6.6, 3],
			[7.6, 3],
			[7.6, 1.3],
			[8.6, 1.3],
		],
		C.teal,
	);
	s.route(
		[
			[6.6, 3],
			[7.6, 3],
			[7.6, 4.7],
			[8.6, 4.7],
		],
		C.teal,
	);
	s.tag(tx.top, "Transmitter", 48);
	s.tag(set.top, "Signed event", 44);
	s.tag(ra.top, "Receiver A", 40);
	s.tag(rb.top, "Receiver B", 40);
	writeFileSync(
		join(OUT, "overview.svg"),
		wrap(
			s,
			"Shared signals overview",
			"A transmitter sends signed security events to two receivers.",
		),
	);
}

// 2. lifecycle: four stages along the platform
{
	const s = scene(720, 420, 14, 6);
	s.platform(0, 0, 14, 6);
	const xs = [0.8, 4, 7.2, 10.4];
	const labels = ["1 Admin action", "2 Signed event", "3 Push or poll", "4 Revoke session"];
	const accents = [C.purple, C.lime, C.teal, C.teal];
	const boxes = xs.map((x, i) => s.cuboid(x, 2, 2, 2, i === 1 ? 0.9 : 1.3, { accent: accents[i] }));
	for (let i = 0; i < 3; i++)
		s.route(
			[
				[xs[i] + 2.15, 3],
				[xs[i + 1] - 0.15, 3],
			],
			i === 1 ? C.teal : C.lime,
		);
	for (const [i, b] of boxes.entries()) s.tag(b.top, labels[i], i % 2 ? 62 : 38);
	writeFileSync(
		join(OUT, "flow.svg"),
		wrap(
			s,
			"Event lifecycle",
			"Four steps: an action happens, theAuth signs an event, it is delivered by push or poll, and the receiver revokes the session.",
		),
	);
}

// 3. push vs poll lanes
{
	const s = scene(720, 440, 13, 8);
	s.platform(0, 0, 13, 8);
	const t1 = s.cuboid(0.8, 0.6, 2, 2, 1.1, { accent: C.purple });
	const r1 = s.cuboid(10, 0.6, 2, 2, 1.1, { accent: C.teal });
	const t2 = s.cuboid(0.8, 5.4, 2, 2, 1.1, { accent: C.purple });
	const r2 = s.cuboid(10, 5.4, 2, 2, 1.1, { accent: C.teal });
	s.route(
		[
			[3, 1.6],
			[9.8, 1.6],
		],
		C.lime,
	);
	s.route(
		[
			[9.8, 6.4],
			[3, 6.4],
		],
		C.teal,
	);
	s.tag(t1.top, "Transmitter", 40);
	s.tag(r1.top, "Receiver", 40);
	s.tag(t2.top, "Transmitter", 40);
	s.tag(r2.top, "Receiver", 40);
	s.tag(s.P(6.4, 1.6, 0.4), "Push: POST SET", 30);
	s.tag(s.P(6.4, 6.4, 0.4), "Poll: ask and ack", 30);
	writeFileSync(
		join(OUT, "delivery.svg"),
		wrap(
			s,
			"Push and poll delivery",
			"Push: the transmitter posts to the receiver. Poll: the receiver asks the transmitter and acknowledges.",
		),
	);
}
