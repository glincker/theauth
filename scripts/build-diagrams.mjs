#!/usr/bin/env node
// Builds the branded isometric docs diagrams. Run: node scripts/build-diagrams.mjs
// Each SVG carries its own title, one line explanation and theauth.dev, so it
// still makes sense when it is found on its own (search, social, slides).
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "docs", "images");
const C = {
	bg: "#06080a",
	teal: "#19d9b8",
	lime: "#eef35f",
	purple: "#8b7cf6",
	red: "#f87171",
	text: "#f4f4f5",
	muted: "#a1a1aa",
	edge: "#2f3f47",
};
const FONT = "Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif";
const MONO = "ui-monospace,JetBrains Mono,Menlo,Consolas,monospace";
const W = 760;
const SCENE_H = 560;
const PLATE_H = 480;
const f = (n) => Math.round(n * 10) / 10;
const wrapText = (t, max) => {
	const out = [];
	let cur = "";
	for (const w of t.split(" ")) {
		if (cur && `${cur} ${w}`.length > max) {
			out.push(cur);
			cur = w;
		} else cur = cur ? `${cur} ${w}` : w;
	}
	if (cur) out.push(cur);
	return out;
};
const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");

const ICONS = {
	agent: (a) =>
		`<rect x=".22" y=".3" width=".56" height=".44" rx=".1" fill="${a}" fill-opacity=".18" stroke="${a}"/><circle cx=".4" cy=".52" r=".05" fill="${C.text}"/><circle cx=".6" cy=".52" r=".05" fill="${C.text}"/><path d="M.5 .3V.16" stroke="${a}"/><circle cx=".5" cy=".14" r=".04" fill="${a}"/>`,
	mark: () =>
		`<rect x=".18" y=".18" width=".64" height=".64" rx=".17" fill="none" stroke="${C.purple}"/><rect x=".32" y=".32" width=".36" height=".36" rx=".1" fill="none" stroke="${C.text}"/><rect x=".44" y=".44" width=".12" height=".12" rx=".04" fill="${C.lime}" stroke="none"/>`,
	server: (a) =>
		[0, 1, 2]
			.map(
				(i) =>
					`<rect x=".2" y="${0.2 + i * 0.22}" width=".6" height=".15" rx=".04" fill="${a}" fill-opacity=".16" stroke="${a}"/><circle cx=".7" cy="${0.275 + i * 0.22}" r=".03" fill="${a}" stroke="none"/>`,
			)
			.join(""),
	user: (a) =>
		`<circle cx=".5" cy=".36" r=".13" fill="${a}" fill-opacity=".18" stroke="${a}"/><path d="M.24 .78C.26 .58 .38 .54 .5 .54S.74 .58 .76 .78Z" fill="${a}" fill-opacity=".18" stroke="${a}"/>`,
	key: (a) =>
		`<circle cx=".34" cy=".5" r=".14" fill="none" stroke="${a}"/><path d="M.48 .5H.82M.7 .5V.62M.78 .5V.58" stroke="${a}"/>`,
	window: (a) =>
		`<rect x=".16" y=".2" width=".68" height=".6" rx=".06" fill="${a}" fill-opacity=".1" stroke="${a}"/><path d="M.16 .36H.84" stroke="${a}"/><circle cx=".25" cy=".28" r=".02" fill="${a}" stroke="none"/><circle cx=".32" cy=".28" r=".02" fill="${a}" stroke="none"/><path d="M.26 .5H.6M.26 .62H.72" stroke="${a}" stroke-opacity=".6"/>`,
	cookie: (a) =>
		`<circle cx=".5" cy=".5" r=".3" fill="${a}" fill-opacity=".14" stroke="${a}"/><circle cx=".42" cy=".42" r=".035" fill="${a}" stroke="none"/><circle cx=".58" cy=".5" r=".035" fill="${a}" stroke="none"/><circle cx=".46" cy=".62" r=".035" fill="${a}" stroke="none"/>`,
	shield: (a) =>
		`<path d="M.5 .16L.78 .27V.5C.78 .66 .66 .78 .5 .84C.34 .78 .22 .66 .22 .5V.27Z" fill="${a}" fill-opacity=".16" stroke="${a}"/><path d="M.37 .5L.47 .6L.64 .4" fill="none" stroke="${a}"/>`,
	db: (a) =>
		`<ellipse cx=".5" cy=".28" rx=".26" ry=".1" fill="${a}" fill-opacity=".2" stroke="${a}"/><path d="M.24 .28V.7C.24 .76 .36 .82 .5 .82S.76 .76 .76 .7V.28M.24 .49C.24 .55 .36 .6 .5 .6S.76 .55 .76 .49" stroke="${a}"/>`,
	term: (a) =>
		`<rect x=".14" y=".22" width=".72" height=".56" rx=".07" fill="${a}" fill-opacity=".1" stroke="${a}"/><path d="M.28 .42L.4 .5L.28 .58M.48 .6H.66" stroke="${a}"/>`,
	bolt: (a) =>
		`<path d="M.55 .14L.3 .54H.48L.42 .86L.7 .44H.52Z" fill="${a}" fill-opacity=".2" stroke="${a}"/>`,
};

function scene(X, Y, caption) {
	const top = 92;
	const lines = wrapText(caption.line, 62);
	const BAND = 66 + lines.length * 20;
	const H = SCENE_H + BAND;
	const u = Math.min((W - 48) / ((X + Y) * 0.866), (PLATE_H - top - 8) / ((X + Y) * 0.5));
	const ox = W / 2 + ((Y - X) / 2) * 0.866 * u;
	const oy = top;
	const P = (x, y, z = 0) => [f(ox + (x - y) * 0.866 * u), f(oy + (x + y) * 0.5 * u - z * u)];
	const pts = (arr) => arr.map((p) => p.join(",")).join(" ");
	const out = [];
	const obstacles = [];
	const groupLabels = [];
	const poly = (arr, fill, stroke = C.edge, extra = "") =>
		`<polygon points="${pts(arr)}" fill="${fill}" stroke="${stroke}" stroke-width="1" stroke-linejoin="round" ${extra}/>`;
	const base = 0.35;

	function platform(x1, y1, x2, y2) {
		out.push(
			poly([P(x1, y2, 0), P(x2, y2, 0), P(x2, y2, base), P(x1, y2, base)], "url(#lf)"),
			poly([P(x2, y1, 0), P(x2, y2, 0), P(x2, y2, base), P(x2, y1, base)], "url(#rf)"),
			poly([P(x1, y1, base), P(x2, y1, base), P(x2, y2, base), P(x1, y2, base)], "url(#pf)"),
		);
		for (let gx = x1 + 1; gx < x2; gx += 1)
			for (let gy = y1 + 1; gy < y2; gy += 1) {
				const [px, py] = P(gx, gy, base);
				out.push(`<circle cx="${px}" cy="${py}" r="1" fill="#46585f" opacity=".6"/>`);
			}
	}

	function icon(kind, x, y, w, d, z, accent) {
		const [ex, ey] = P(x, y, z);
		const m = [w * 0.866 * u, w * 0.5 * u, -d * 0.866 * u, d * 0.5 * u, ex, ey].map(
			(n) => f(n * 100) / 100,
		);
		out.push(
			`<g transform="matrix(${m.join(" ")})" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vector-effect:non-scaling-stroke">${ICONS[kind](accent).replace(/<(\w+) /g, '<$1 vector-effect="non-scaling-stroke" ')}</g>`,
		);
	}

	function cuboid(x, y, w, d, hh, { accent = C.teal, kind } = {}) {
		const z0 = base;
		const z1 = base + hh;
		const pad = 0.28;
		// contact shadow and accent glow on the platform
		const sh = [
			P(x - pad + 0.25, y - pad + 0.25, z0),
			P(x + w + pad + 0.25, y - pad + 0.25, z0),
			P(x + w + pad + 0.25, y + d + pad + 0.25, z0),
			P(x - pad + 0.25, y + d + pad + 0.25, z0),
		];
		out.push(`<polygon points="${pts(sh)}" fill="#000" opacity=".6" filter="url(#bl)"/>`);
		const gl = [
			P(x - 0.1, y - 0.1, z0),
			P(x + w + 0.1, y - 0.1, z0),
			P(x + w + 0.1, y + d + 0.1, z0),
			P(x - 0.1, y + d + 0.1, z0),
		];
		out.push(`<polygon points="${pts(gl)}" fill="${accent}" opacity=".16" filter="url(#bl)"/>`);
		out.push(
			poly(
				[P(x, y + d, z0), P(x + w, y + d, z0), P(x + w, y + d, z1), P(x, y + d, z1)],
				"url(#lf)",
			),
			poly(
				[P(x + w, y, z0), P(x + w, y + d, z0), P(x + w, y + d, z1), P(x + w, y, z1)],
				"url(#rf)",
			),
			poly(
				[P(x, y, z1), P(x + w, y, z1), P(x + w, y + d, z1), P(x, y + d, z1)],
				"url(#tf)",
				"#3d5058",
			),
		);
		// bevel highlight on the near top edges
		out.push(
			`<polyline points="${pts([P(x, y + d, z1), P(x + w, y + d, z1), P(x + w, y, z1)])}" fill="none" stroke="#52666f" stroke-width="1.2"/>`,
		);
		// glowing base edge
		out.push(
			`<polyline points="${pts([P(x, y + d, z0 + 0.1), P(x + w, y + d, z0 + 0.1), P(x + w, y, z0 + 0.1)])}" fill="none" stroke="${accent}" stroke-width="1.8" opacity=".95"/>`,
		);
		if (kind) icon(kind, x, y, w, d, z1, accent);
		const cs = [x, x + w].flatMap((px) =>
			[y, y + d].flatMap((py) => [z0, z1].map((pz) => P(px, py, pz))),
		);
		const r = {
			l: Math.min(...cs.map((c) => c[0])) - 4,
			r: Math.max(...cs.map((c) => c[0])) + 4,
			t: Math.min(...cs.map((c) => c[1])) - 4,
			b: Math.max(...cs.map((c) => c[1])) + 4,
		};
		obstacles.push(r);
		return { top: P(x + w / 2, y + d / 2, z1), front: P(x + w, y + d, z0), rect: r };
	}

	// Routes are lifted pipes: a soft shadow on the plate, thin stems at the
	// ends, a rounded pipe with a highlight, and a flowing dash on top.
	function route(path, color = C.teal, z = 0.95) {
		const lift = path.map(([x, y]) => P(x, y, z));
		const flat = path.map(([x, y]) => P(x + 0.18, y + 0.18, base + 0.02));
		const id = { [C.teal]: "mt", [C.lime]: "ml", [C.purple]: "mp", [C.red]: "mr" }[color] ?? "mt";
		const line = (arr) => pts(arr);
		out.push(
			`<polyline points="${line(flat)}" fill="none" stroke="#000" stroke-opacity=".5" stroke-width="7" stroke-linecap="round" stroke-linejoin="round" filter="url(#sb)"/>`,
		);
		for (const i of [0, path.length - 1]) {
			const [px, py] = lift[i];
			const [fx, fy] = P(path[i][0], path[i][1], base);
			out.push(
				`<line x1="${px}" y1="${py}" x2="${fx}" y2="${fy}" stroke="${color}" stroke-opacity=".45" stroke-width="1.5" stroke-dasharray="2 3"/>`,
			);
		}
		out.push(
			`<polyline points="${line(lift)}" fill="none" stroke="#04070a" stroke-width="9" stroke-linecap="round" stroke-linejoin="round"/>`,
			`<polyline points="${line(lift)}" fill="none" stroke="${color}" stroke-opacity=".85" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/>`,
			`<polyline points="${line(lift.map(([x, y]) => [x, y - 1.6]))}" fill="none" stroke="#fff" stroke-opacity=".45" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>`,
			`<polyline class="flow" points="${line(lift)}" fill="none" stroke="#04070a" stroke-opacity=".55" stroke-width="2.6" stroke-dasharray="2 10" stroke-linecap="round" stroke-linejoin="round" marker-end="url(#${id})"/>`,
		);
		const [sx, sy] = lift[0];
		out.push(
			`<circle cx="${sx}" cy="${sy}" r="6" fill="${color}" stroke="#04070a" stroke-width="2"/><circle cx="${sx - 1.5}" cy="${sy - 1.5}" r="2" fill="#fff" fill-opacity=".6"/>`,
		);
	}

	// A dashed bubble on the platform that groups related nodes.
	function group(x1, y1, x2, y2, label, color = C.teal) {
		const q = [P(x1, y1, base), P(x2, y1, base), P(x2, y2, base), P(x1, y2, base)];
		out.push(
			`<polygon points="${pts(q)}" fill="${color}" fill-opacity=".05" stroke="${color}" stroke-opacity=".55" stroke-width="1.5" stroke-dasharray="6 5" stroke-linejoin="round"/>`,
		);
		const [lx, ly] = P(x1, y2, base);
		groupLabels.push({ lx, ly, label, color });
	}

	const tags = [];
	const callouts = [];
	function tag([x, y], label, lift = 40) {
		tags.push({ x, y, label, lift });
	}

	function callout([x, y], n, text, dy = 46, dx = 0) {
		callouts.push({ x, y, n, text, dy, dx });
	}

	// Place pills and callouts after everything is known. Each one tries
	// candidate spots until it clears every node, bubble and label.
	function placeTags() {
		const boxes = obstacles.map((o) => ({ ...o }));
		const res = [];
		const hit = (r) =>
			boxes.some((o) => r.l < o.r + 6 && r.r > o.l - 6 && r.t < o.b + 6 && r.b > o.t - 6);
		const inside = (r) => r.l >= 8 && r.r <= W - 8 && r.t >= 56 && r.b <= SCENE_H - 8;
		const owner = (x, y) => boxes.find((o) => x >= o.l && x <= o.r && y >= o.t && y <= o.b);

		for (const g of groupLabels) {
			const w = g.label.length * 8 + 22;
			const spots = [
				[0, 0],
				[0, 28],
				[-50, 14],
				[50, 14],
				[-90, 0],
				[90, 0],
				[0, -28],
				[-60, 44],
			];
			let chosen = spots[0];
			for (const sp of spots) {
				const cx = Math.min(Math.max(g.lx - 6 + sp[0], w / 2 + 8), W - w / 2 - 8);
				const r = { l: cx - w / 2, r: cx + w / 2, t: g.ly + sp[1] - 4, b: g.ly + sp[1] + 20 };
				if (inside(r) && !hit(r)) {
					chosen = sp;
					break;
				}
			}
			const cx = Math.min(Math.max(g.lx - 6 + chosen[0], w / 2 + 8), W - w / 2 - 8);
			const cy = g.ly + chosen[1];
			boxes.push({ l: cx - w / 2, r: cx + w / 2, t: cy - 4, b: cy + 20 });
			res.push(
				`<rect x="${f(cx - w / 2)}" y="${f(cy - 4)}" width="${f(w)}" height="24" rx="12" fill="#0a0f12" stroke="${g.color}" stroke-opacity=".7"/><text x="${f(cx)}" y="${f(cy + 12)}" text-anchor="middle" font-size="12.5" fill="${g.color}" font-family="${MONO}">${esc(g.label)}</text>`,
			);
		}

		for (const t of tags) {
			const w = Math.max(72, t.label.length * 8.6 + 28);
			const below = t.lift < 0;
			const own = owner(t.x, below ? t.y - 6 : t.y + 6);
			const dir = below ? 1 : -1;
			let ty = t.y - t.lift;
			if (own) ty = below ? Math.max(ty, own.b + 24) : Math.min(ty, own.t - 24);
			let best = null;
			for (let k = 0; k < 10 && !best; k++) {
				for (const sgn of [1, -1]) {
					const cy = ty + dir * sgn * k * 18;
					const px = Math.min(Math.max(t.x, w / 2 + 10), W - w / 2 - 10);
					const r = { l: px - w / 2, r: px + w / 2, t: cy - 15, b: cy + 15 };
					if (inside(r) && !hit(r)) {
						best = { px, cy, r };
						break;
					}
				}
			}
			if (!best) {
				const px = Math.min(Math.max(t.x, w / 2 + 10), W - w / 2 - 10);
				best = {
					px,
					cy: ty,
					r: { l: px - w / 2, r: px + w / 2, t: ty - 15, b: ty + 15 },
					bad: true,
				};
				console.warn(`overlap: tag "${t.label}"`);
				process.exitCode = 1;
			}
			boxes.push(best.r);
			const { px, cy } = best;
			const goesDown = cy > t.y;
			const l1 = goesDown ? t.y : cy + 15;
			const l2 = goesDown ? cy - 15 : t.y;
			res.push(
				`<line x1="${t.x}" y1="${l1}" x2="${t.x}" y2="${l2}" stroke="${C.teal}" stroke-width="1.5"/><circle cx="${t.x}" cy="${t.y}" r="3" fill="${C.teal}"/>`,
				`<rect x="${f(px - w / 2)}" y="${cy - 15}" width="${f(w)}" height="30" rx="15" fill="#0b1013" stroke="#3a4d56"/>`,
				`<text x="${px}" y="${cy + 5}" text-anchor="middle" font-size="14.5" fill="${C.text}" font-family="${MONO}">${esc(t.label)}</text>`,
			);
		}

		for (const c of callouts) {
			const ls = wrapText(c.text, 24).slice(0, 2);
			const w = Math.max(...ls.map((l) => l.length)) * 7.4 + 54;
			const h = ls.length > 1 ? 46 : 36;
			const cands = [];
			for (const dx of [0, -120, 120, -240, 240, -330, 330, -400, 400])
				for (const dy of [0, 30, 60, 90, 120, -30, -60])
					cands.push({ dx, dy, c: Math.abs(dx) * 0.6 + Math.abs(dy) });
			cands.sort((a, b) => a.c - b.c);
			let best = null;
			for (const k of cands) {
				const cx = Math.min(Math.max(c.x + c.dx + k.dx, w / 2 + 8), W - w / 2 - 8);
				const cy = c.y + c.dy + k.dy;
				const r = { l: cx - w / 2, r: cx + w / 2, t: cy - h / 2, b: cy + h / 2 };
				if (inside(r) && !hit(r)) {
					best = { cx, cy, r };
					break;
				}
			}
			if (!best) {
				const cx = Math.min(Math.max(c.x + c.dx, w / 2 + 8), W - w / 2 - 8);
				const cy = Math.min(c.y + c.dy, SCENE_H - 30);
				best = { cx, cy, r: { l: cx - w / 2, r: cx + w / 2, t: cy - h / 2, b: cy + h / 2 } };
				console.warn(`overlap: callout "${c.text}"`);
				process.exitCode = 1;
			}
			boxes.push(best.r);
			const { cx, cy } = best;
			res.push(
				`<path d="M${c.x} ${c.y}L${f(cx)} ${f(cy + (cy > c.y ? -h / 2 : h / 2))}" stroke="${C.lime}" stroke-opacity=".55" stroke-width="1.5" stroke-dasharray="2 4" stroke-linecap="round"/><circle cx="${c.x}" cy="${c.y}" r="3" fill="${C.lime}"/>`,
				`<rect x="${f(cx - w / 2)}" y="${f(cy - h / 2)}" width="${f(w)}" height="${h}" rx="${h / 2}" fill="#0d1519" stroke="${C.lime}" stroke-opacity=".5"/>`,
				`<circle cx="${f(cx - w / 2 + 19)}" cy="${cy}" r="10" fill="${C.lime}"/><text x="${f(cx - w / 2 + 19)}" y="${cy + 4.5}" text-anchor="middle" font-size="12.5" font-weight="700" fill="${C.bg}">${c.n}</text>`,
				...ls.map(
					(l, k) =>
						`<text x="${f(cx - w / 2 + 36)}" y="${f(cy + (ls.length > 1 ? -2 + k * 15 : 4.5))}" font-size="12.5" fill="${C.text}">${esc(l)}</text>`,
				),
			);
		}
		return res;
	}

	function chip([x, y], label) {
		const w = label.length * 8.6 + 24;
		obstacles.push({ l: x - w / 2 - 2, r: x + w / 2 + 2, t: y - 15, b: y + 15 });
		out.push(
			`<rect x="${f(x - w / 2)}" y="${y - 13}" width="${f(w)}" height="26" rx="13" fill="#0b1013" stroke="${C.teal}" stroke-opacity=".6"/><text x="${x}" y="${y + 5}" text-anchor="middle" font-size="13.5" fill="${C.text}" font-family="${MONO}">${esc(label)}</text>`,
		);
	}

	function step([x, y], n) {
		obstacles.push({ l: x - 16, r: x + 16, t: y - 16, b: y + 16 });
		out.push(
			`<circle cx="${x}" cy="${y}" r="14" fill="${C.lime}"/><text x="${x}" y="${y + 5.5}" text-anchor="middle" font-size="15" font-weight="700" fill="${C.bg}">${n}</text>`,
		);
	}

	function blocked([x, y]) {
		const [px, py] = P(x, y, 0.45);
		out.push(
			`<circle cx="${px}" cy="${py}" r="12" fill="${C.red}"/><path d="M${px - 4.5} ${py - 4.5}L${px + 4.5} ${py + 4.5}M${px + 4.5} ${py - 4.5}L${px - 4.5} ${py + 4.5}" stroke="${C.bg}" stroke-width="2.5" stroke-linecap="round"/>`,
		);
	}

	function svg() {
		const { title, alt } = caption;
		return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" role="img" aria-labelledby="t d" font-family="${FONT}">
<title id="t">${esc(title)}</title><desc id="d">${esc(alt)}</desc>
<defs>
<radialGradient id="g1" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(0 0) scale(${W * 0.5} ${H * 0.8})"><stop stop-color="${C.teal}" stop-opacity=".30"/><stop offset="1" stop-color="${C.teal}" stop-opacity="0"/></radialGradient>
<radialGradient id="g2" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(${W * 0.5} 0) scale(${W * 0.35} ${H * 0.6})"><stop stop-color="${C.purple}" stop-opacity=".24"/><stop offset="1" stop-color="${C.purple}" stop-opacity="0"/></radialGradient>
<radialGradient id="g3" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(${W} 0) scale(${W * 0.45} ${H * 0.8})"><stop stop-color="${C.lime}" stop-opacity=".22"/><stop offset="1" stop-color="${C.lime}" stop-opacity="0"/></radialGradient>
<linearGradient id="tf" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#27333a"/><stop offset="1" stop-color="#182025"/></linearGradient>
<linearGradient id="lf" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#172025"/><stop offset="1" stop-color="#0a0f12"/></linearGradient>
<linearGradient id="rf" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#0f171b"/><stop offset="1" stop-color="#070b0d"/></linearGradient>
<linearGradient id="pf" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#162026"/><stop offset="1" stop-color="#0f171b"/></linearGradient>
<marker id="mt" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M1 1L9 5L1 9" fill="#04070a" stroke="${C.teal}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></marker>
<marker id="ml" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M1 1L9 5L1 9" fill="#04070a" stroke="${C.lime}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></marker>
<marker id="mp" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M1 1L9 5L1 9" fill="#04070a" stroke="${C.purple}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></marker>
<marker id="mr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M1 1L9 5L1 9" fill="#04070a" stroke="${C.red}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></marker>
<style>.flow{animation:flow 1.8s linear infinite}@keyframes flow{to{stroke-dashoffset:-20}}@media (prefers-reduced-motion:reduce){.flow{animation:none}}</style>
<filter id="sb" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="2.5"/></filter>
<filter id="bl" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="7"/></filter>
<filter id="n" x="0" y="0" width="100%" height="100%"><feTurbulence type="fractalNoise" baseFrequency=".85" numOctaves="2" seed="11" stitchTiles="stitch"/><feColorMatrix values="0 0 0 0 1  0 0 0 0 1  0 0 0 0 1  0 0 0 .7 0"/></filter>
</defs>
<rect width="${W}" height="${H}" rx="16" fill="${C.bg}"/>
<rect width="${W}" height="${H}" rx="16" fill="url(#g1)"/><rect width="${W}" height="${H}" rx="16" fill="url(#g2)"/><rect width="${W}" height="${H}" rx="16" fill="url(#g3)"/>
<rect width="${W}" height="${H}" rx="16" filter="url(#n)" opacity=".10"/>
${[...out, ...placeTags()].join("\n")}
<g transform="translate(24 22)"><rect x=".75" y=".75" width="26.5" height="26.5" rx="7.5" fill="none" stroke="${C.purple}" stroke-width="2"/><rect x="7" y="7" width="14" height="14" rx="4" fill="none" stroke="${C.purple}" stroke-width="1.6"/><rect x="11" y="11" width="6" height="6" rx="1.8" fill="${C.lime}"/><text x="38" y="20" font-size="17" font-weight="600" fill="${C.text}">theAuth</text></g>
<rect x="0" y="${H - BAND}" width="${W}" height="${BAND}" fill="#000" opacity=".35"/>
<line x1="0" y1="${H - BAND}" x2="${W}" y2="${H - BAND}" stroke="#26343b"/>
<text x="24" y="${H - BAND + 32}" font-size="20" font-weight="650" fill="${C.text}">${esc(title)}</text>
${lines.map((l, i) => `<text x="24" y="${H - BAND + 56 + i * 20}" font-size="14.5" fill="${C.muted}">${esc(l)}</text>`).join("\n")}
<text x="${W - 24}" y="40" text-anchor="end" font-size="13" fill="${C.lime}" font-family="${MONO}">theauth.dev</text>
</svg>
`;
	}

	return { P, platform, group, cuboid, route, tag, callout, chip, step, blocked, svg };
}

function save(dir, name, s) {
	mkdirSync(join(ROOT, dir), { recursive: true });
	writeFileSync(join(ROOT, dir, `${name}.svg`), s.svg());
}

// Layout helpers: nodes sit on a 10 by 10 platform, chains run along the
// anti-diagonal so they read left to right on screen.
const box = (cx, cy, size = 1.8) => [cx - size / 2, cy - size / 2, size, size];
const along = ([ax, ay], [bx, by], gap = 1.15) => {
	const dx = Math.sign(bx - ax);
	const dy = Math.sign(by - ay);
	return [
		[ax + dx * gap, ay + dy * gap],
		[bx - dx * gap, by - dy * gap],
	];
};

// shared signals: overview
{
	const s = scene(10, 10, {
		title: "Shared signals with theAuth",
		line: "A transmitter sends signed security events, and every receiver acts on them within seconds.",
		alt: "A theAuth transmitter sends a signed security event to two receivers, which revoke sessions or run a custom handler.",
		notes: [
			"An event happens, such as a ban or a password change.",
			"theAuth signs it and queues it per stream.",
			"Every receiver verifies it and acts on it.",
		],
	});
	s.platform(0, 0, 10, 10);
	s.group(6.2, 0.6, 9.9, 8.8, "Receivers", C.teal);
	const tx = [1.7, 8.3];
	const ev = [4.6, 5.4];
	const ra = [7.4, 2.2];
	const rb = [8.6, 7.2];
	const a = s.cuboid(...box(...tx, 2), 1.5, { accent: C.purple, kind: "mark" });
	const b = s.cuboid(...box(...ev, 1.4), 0.6, { accent: C.lime, kind: "bolt" });
	const c = s.cuboid(...box(...ra), 1.8, { accent: C.teal, kind: "server" });
	const d = s.cuboid(...box(...rb), 1.1, { accent: C.teal, kind: "server" });
	s.route(along(tx, ev, 1.4), C.lime);
	s.route(along(ev, ra, 1.2), C.teal);
	s.route(
		[
			[ev[0] + 0.9, ev[1] + 0.4],
			[rb[0] - 1.2, rb[1]],
		],
		C.teal,
	);
	s.tag(a.top, "Transmitter", 50);
	s.tag(b.top, "Signed event", 46);
	s.tag(c.top, "Receiver A", 44);
	s.tag(d.front, "Receiver B", -28);
	const st = [4.2, 8.8];
	const sd = s.cuboid(...box(...st, 1.6), 0.8, { accent: C.lime, kind: "db" });
	s.route(
		[
			[ev[0] + 0.3, ev[1] + 1.1],
			[st[0] - 0.2, st[1] - 1.1],
		],
		C.lime,
	);
	s.tag(sd.front, "Stream store", -30);
	s.callout(s.P(3.8, 4.2, 0.45), 1, "Event is signed and queued", 70, -20);
	s.callout(c.front, 2, "Receiver verifies it", 40, 30);
	s.callout(d.front, 3, "Sessions revoked", 76, -10);
	save("shared-signals", "theauth-shared-signals-overview", s);
}

// shared signals: lifecycle
{
	const s = scene(10, 10, {
		title: "Shared signals event lifecycle",
		line: "An admin action becomes a signed event, is pushed or polled, and the receiver revokes the session.",
		alt: "Four steps: an admin action happens, theAuth signs an event, it is delivered by push or poll, and the receiver revokes the session.",
		notes: [
			"An admin bans a user or revokes a session.",
			"theAuth signs a SET and stores it for the stream.",
			"It is pushed to the receiver or fetched by poll.",
			"The receiver verifies it and revokes the session.",
		],
	});
	s.platform(0, 0, 10, 10);
	s.group(5.2, 0.2, 9.9, 4.9, "Receiver", C.teal);
	const cs = [
		[1.3, 8.7],
		[3.8, 6.2],
		[6.2, 3.8],
		[8.7, 1.3],
	];
	const spec = [
		{ accent: C.purple, kind: "user", h: 1.3 },
		{ accent: C.lime, kind: "mark", h: 1 },
		{ accent: C.teal, kind: "server", h: 1.3 },
		{ accent: C.teal, kind: "shield", h: 1.3 },
	];
	const labels = ["1 Admin action", "2 Signed event", "3 Push or poll", "4 Revoke session"];
	const boxes = cs.map((c, i) => s.cuboid(...box(...c, 1.6), spec[i].h, spec[i]));
	for (let i = 0; i < 3; i++) s.route(along(cs[i], cs[i + 1], 1.0), i === 1 ? C.teal : C.lime);
	for (const [i, b] of boxes.entries()) s.tag(b.top, labels[i], i % 2 ? 66 : 42);
	const cl = [
		"Ban or revoke",
		"SET signed and stored",
		"Pushed or polled",
		"Verified, session revoked",
	];
	for (const [i, b] of boxes.entries()) s.callout(b.front, i + 1, cl[i], 40 + (i % 2) * 54);
	save("shared-signals", "theauth-shared-signals-lifecycle", s);
}

// shared signals: push vs poll
{
	const s = scene(10, 10, {
		title: "Push and poll delivery",
		line: "Push posts events to the receiver. Poll lets the receiver fetch and acknowledge on its own schedule.",
		alt: "Push: the transmitter posts a signed event to the receiver. Poll: the receiver asks the transmitter for events and acknowledges them.",
		notes: [
			"Push: the transmitter POSTs each event and retries with backoff.",
			"Poll: the receiver asks for events and acknowledges them.",
		],
	});
	s.platform(0, 0, 10, 10);
	const t1 = [0.9, 5.1];
	const r1 = [5.1, 0.9];
	const t2 = [4.9, 9.1];
	const r2 = [9.1, 4.9];
	const a = s.cuboid(...box(...t1, 1.7), 1.1, { accent: C.purple, kind: "mark" });
	const b = s.cuboid(...box(...r1, 1.7), 1.1, { accent: C.teal, kind: "server" });
	const c = s.cuboid(...box(...t2, 1.7), 1.1, { accent: C.purple, kind: "mark" });
	const d = s.cuboid(...box(...r2, 1.7), 1.1, { accent: C.teal, kind: "server" });
	s.route(along(t1, r1, 1.1), C.lime);
	s.route(along(r2, t2, 1.1), C.teal);
	s.tag(a.top, "Transmitter", 44);
	s.tag(b.top, "Receiver", 44);
	s.tag(c.front, "Transmitter", -28);
	s.tag(d.front, "Receiver", -28);
	s.callout(s.P(3, 3, 0.95), 1, "POST, retries", 58);
	s.callout(s.P(7, 7, 0.45), 2, "Asks for events, then acks", 58);
	save("shared-signals", "theauth-shared-signals-push-poll", s);
}

// quickstart: add theAuth to an existing app
{
	const s = scene(10, 10, {
		title: "Add theAuth to an existing app",
		line: "Mount one handler, sign users in, and read the session in any protected route.",
		alt: "Your app mounts the theAuth handler, theAuth issues a session cookie, and protected routes read that session.",
		notes: [
			"Create theAuth and mount one handler.",
			"Users sign in and get a session cookie.",
			"Read the session in any protected route.",
			"Sessions and users live in your own database.",
		],
	});
	s.platform(0, 0, 10, 10);
	s.group(0.2, 2.6, 7.4, 9.9, "Your server", C.purple);
	const cs = [
		[1.3, 8.7],
		[3.8, 6.2],
		[6.2, 3.8],
		[8.7, 1.3],
	];
	const spec = [
		{ accent: C.teal, kind: "window", h: 1.2 },
		{ accent: C.purple, kind: "mark", h: 1.5 },
		{ accent: C.lime, kind: "cookie", h: 0.8 },
		{ accent: C.teal, kind: "shield", h: 1.2 },
	];
	const labels = ["Your app", "theAuth handler", "Session cookie", "Protected route"];
	const boxes = cs.map((c, i) => s.cuboid(...box(...c, 1.6), spec[i].h, spec[i]));
	for (let i = 0; i < 3; i++) s.route(along(cs[i], cs[i + 1], 1.0), i === 1 ? C.lime : C.teal);
	for (const [i, b] of boxes.entries()) s.tag(b.top, labels[i], i % 2 ? 66 : 42);
	const dbp = [4.2, 8.8];
	const dd = s.cuboid(...box(...dbp, 1.6), 0.9, { accent: C.lime, kind: "db" });
	s.route(
		[
			[cs[1][0] + 0.2, cs[1][1] + 1.0],
			[dbp[0] + 0.1, dbp[1] - 1.1],
		],
		C.lime,
	);
	s.tag(dd.front, "Your database", -30);
	const cl = [
		"Mount one handler",
		"Sign in sets a cookie",
		"Read the session",
		"Data stays in your DB",
	];
	for (const [i, b] of boxes.entries()) s.callout(b.front, i + 1, cl[i], 44 + (i % 2) * 52);
	save("diagrams", "theauth-add-to-existing-app", s);
}

// dpop
{
	const s = scene(10, 10, {
		title: "DPoP sender-constrained tokens",
		line: "The token is bound to the client's key, so a copy stolen from logs fails without the matching proof.",
		alt: "A client sends a token and a DPoP proof signed with its key to the resource server, which accepts it. A thief with only the token is refused.",
		notes: [
			"theAuth issues a token bound to the client key.",
			"The client sends the token with a signed proof.",
			"A thief with only the token is refused.",
		],
	});
	s.platform(0, 0, 10, 10);
	s.group(7.2, 0.5, 9.9, 3.2, "Your API", C.teal);
	const cl = [1.7, 8.3];
	const rs = [8.3, 1.7];
	const th = [2.6, 2.4];
	const a = s.cuboid(...box(...cl), 1.2, { accent: C.purple, kind: "key" });
	const b = s.cuboid(...box(...rs), 1.2, { accent: C.teal, kind: "server" });
	const c = s.cuboid(...box(...th, 1.6), 0.8, { accent: C.red, kind: "user" });
	s.route(along(cl, rs, 1.15), C.lime);
	s.route(
		[
			[th[0] + 1, th[1] - 0.1],
			[rs[0] - 1.3, rs[1] - 0.2],
		],
		C.red,
	);
	s.blocked([6.2, 1.6]);
	s.tag(a.top, "Client + key", 44);
	s.tag(b.top, "Resource server", 44);
	s.tag(c.top, "Thief: token only", 40);
	s.chip(s.P(5, 5, 0.45), "token + proof");
	const ts = [3.9, 8.8];
	const tsb = s.cuboid(...box(...ts, 1.5), 1.2, { accent: C.purple, kind: "mark" });
	s.route(
		[
			[ts[0] - 0.9, ts[1] - 0.2],
			[cl[0] + 1.0, cl[1] + 0.3],
		],
		C.purple,
	);
	s.tag(tsb.front, "theAuth issues a bound token", -30);
	s.callout(tsb.front, 1, "Token bound to the key", 70, 60);
	s.callout(a.front, 2, "Proof signed per request", 46);
	s.callout(c.front, 3, "Stolen token refused", 40, -30);
	save("diagrams", "theauth-dpop-token-binding", s);
}

// session hardening: bound stateless cookies
{
	const s = scene(10, 10, {
		title: "Stateless sessions bound to the user",
		line: "The token cookie is sealed against the identity cookie, so a copy from another user is refused.",
		alt: "A browser holds an identity cookie and a token cookie. The server checks that the token cookie is bound to the identity cookie and refuses a token cookie taken from another user.",
		notes: [
			"The browser holds an identity cookie and a token cookie.",
			"The token cookie is sealed against the identity cookie.",
			"A token cookie from another user fails the check.",
		],
	});
	s.platform(0, 0, 10, 10);
	s.group(7.7, 0.2, 9.9, 2.6, "Server", C.purple);
	const cs = [
		[1.3, 8.7],
		[3.8, 6.2],
		[6.2, 3.8],
		[8.7, 1.3],
	];
	const spec = [
		{ accent: C.teal, kind: "window", h: 1.2 },
		{ accent: C.lime, kind: "cookie", h: 0.8 },
		{ accent: C.teal, kind: "cookie", h: 0.8 },
		{ accent: C.purple, kind: "shield", h: 1.3 },
	];
	const labels = ["Browser", "Identity cookie", "Token cookie", "Server checks binding"];
	const boxes = cs.map((c, i) => s.cuboid(...box(...c, 1.6), spec[i].h, spec[i]));
	for (let i = 0; i < 3; i++) s.route(along(cs[i], cs[i + 1], 1.0), i === 1 ? C.teal : C.lime);
	for (const [i, b] of boxes.entries()) s.tag(b.top, labels[i], i % 2 ? 66 : 42);
	const th = [7.6, 7.2];
	const t = s.cuboid(...box(...th, 1.5), 0.7, { accent: C.red, kind: "user" });
	s.route(
		[
			[th[0] + 0.9, th[1] + 0.6],
			[cs[2][0] - 0.9, cs[2][1] - 0.7],
		],
		C.red,
	);
	s.blocked([6.9, 5.7]);
	s.tag(t.front, "Cookie from another user", -30);
	const cl = [
		"Two cookies",
		"Token sealed to identity",
		"Binding checked",
		"Foreign cookie refused",
	];
	for (const [i, b] of boxes.entries()) s.callout(b.front, i + 1, cl[i], 44 + (i % 2) * 52);
	save("diagrams", "theauth-stateless-session-binding", s);
}

// oidc provider
{
	const s = scene(10, 10, {
		title: "theAuth as an OpenID Connect provider",
		line: "Apps send users to theAuth, get an ID token and userinfo back, and are told when the user signs out.",
		alt: "A client app redirects a user to theAuth, receives an ID token and userinfo, and a second app is notified by back-channel logout.",
		notes: [
			"The app redirects the user to theAuth.",
			"theAuth returns an ID token and userinfo.",
			"Other apps hear about sign-out through back-channel logout.",
		],
	});
	s.platform(0, 0, 10, 10);
	s.group(3.8, 3.8, 7.6, 9.7, "theAuth", C.purple);
	const ca = [1.7, 8.3];
	const op = [5, 5];
	const cb = [8.3, 1.7];
	const us = [5.8, 8.6];
	const a = s.cuboid(...box(...ca), 1.2, { accent: C.teal, kind: "window" });
	const b = s.cuboid(...box(...op, 2.2), 1.6, { accent: C.purple, kind: "mark" });
	const c = s.cuboid(...box(...cb), 1.2, { accent: C.teal, kind: "window" });
	const d = s.cuboid(...box(...us, 1.6), 0.9, { accent: C.lime, kind: "db" });
	s.route(along(ca, op, 1.3), C.lime);
	s.route(along(op, cb, 1.3), C.teal);
	s.route(
		[
			[op[0] + 0.2, op[1] + 1.3],
			[us[0] - 0.2, us[1] - 1.1],
		],
		C.lime,
	);
	s.tag(a.top, "Client app", 44);
	s.tag(b.top, "theAuth OpenID provider", 52);
	s.tag(c.top, "Second app", 44);
	s.tag(d.front, "Users and sessions", -30);
	s.step(s.P(3.2, 6.8, 0.45), 1);
	s.step(s.P(6.8, 3.2, 0.45), 2);
	s.callout(a.front, 1, "Redirect to sign in", 44);
	s.callout(b.front, 2, "ID token and userinfo", 56, 40);
	s.callout(c.front, 3, "Back-channel logout", 44);
	save("diagrams", "theauth-oidc-provider-flow", s);
}

// adapters: one core
{
	const s = scene(10, 10, {
		title: "One core, every framework",
		line: "The core speaks Web Request and Response, and a thin adapter mounts it in your framework.",
		alt: "A single theAuth core connected to five framework adapters: Next.js, Express, Hono, Fastify and SvelteKit.",
		notes: [
			"The core only speaks Web Request and Response.",
			"A thin adapter wires it into each framework.",
		],
	});
	s.platform(0, 0, 10, 10);
	const core = [5, 5];
	const ring = [
		["Next.js", [1.5, 5]],
		["Express", [5, 1.5]],
		["Hono", [8.3, 2]],
		["Fastify", [7.3, 7.3]],
		["SvelteKit", [2, 8.2]],
	];
	const nodes = ring.map(([label, pos], i) => {
		const b = s.cuboid(...box(...pos, 1.4), 0.7, {
			accent: i % 2 ? C.lime : C.teal,
			kind: "window",
		});
		const vec = [core[0] - pos[0], core[1] - pos[1]];
		const len = Math.hypot(...vec);
		const n = vec.map((v) => v / len);
		s.route(
			[
				[pos[0] + n[0] * 1.0, pos[1] + n[1] * 1.0],
				[core[0] - n[0] * 1.5, core[1] - n[1] * 1.5],
			],
			i % 2 ? C.lime : C.teal,
		);
		return { label, b, below: pos[1] > 6 };
	});
	const cb = s.cuboid(...box(...core, 2.2), 1.6, { accent: C.purple, kind: "mark" });
	s.tag(cb.front, "theAuth core", -34);
	for (const n of nodes) {
		if (n.below) s.tag(n.b.front, n.label, -28);
		else s.tag(n.b.top, n.label, 36);
	}
	save("diagrams", "theauth-adapters-one-core", s);
}

// theauth add
{
	const s = scene(10, 10, {
		title: "theauth add copies components into your app",
		line: "The CLI pulls a component from the registry and writes the source into your repo, so you own it.",
		alt: "The theauth add command fetches a component from the theAuth registry and writes its source files into your application.",
		notes: [
			"The CLI reads a component from the registry.",
			"It writes the source files into your repo.",
			"You own and can edit the code.",
		],
	});
	s.platform(0, 0, 10, 10);
	const cs = [
		[1.5, 8.5],
		[5, 5],
		[8.5, 1.5],
	];
	const spec = [
		{ accent: C.lime, kind: "db", h: 1.1 },
		{ accent: C.purple, kind: "term", h: 1.3 },
		{ accent: C.teal, kind: "window", h: 1.5 },
	];
	const labels = ["theauth registry", "theauth add sign-in", "Your app source"];
	const boxes = cs.map((c, i) => s.cuboid(...box(...c, 1.8), spec[i].h, spec[i]));
	s.route(along(cs[0], cs[1], 1.3), C.lime);
	s.route(along(cs[1], cs[2], 1.3), C.teal);
	for (const [i, b] of boxes.entries()) s.tag(b.top, labels[i], i === 1 ? 54 : 42);
	const own = s.cuboid(...box(5.6, 8.4, 1.5), 0.8, { accent: C.teal, kind: "shield" });
	s.route(
		[
			[cs[2][0] - 0.8, cs[2][1] + 1],
			[6.6, 7.4],
		],
		C.teal,
	);
	s.tag(own.front, "You own the code", -30);
	s.callout(boxes[0].front, 1, "Reads from the registry", 44);
	s.callout(boxes[1].front, 2, "Writes source files", 44);
	save("diagrams", "theauth-add-components-cli", s);
}
