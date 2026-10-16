#!/usr/bin/env node
// Builds branded terminal screenshots from real example output.
// Run: node scripts/build-terminal-shots.mjs  (needs Chrome and ImageMagick)
// Input: scripts/terminal-shots.json. Output: docs/images/terminal/<name>.jpg,
// <name>-og.jpg and manifest.json. Set CHROME / MAGICK to override tool paths.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, "..", "docs", "images", "terminal");
const BUILD = join(HERE, ".terminal-build");
const CHROME = process.env.CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const MAGICK = process.env.MAGICK ?? "/opt/homebrew/bin/magick";

const C = {
	bg: "#06080a",
	teal: "#19d9b8",
	lime: "#eef35f",
	purple: "#8b7cf6",
	green: "#4ade80",
	amber: "#fbbf24",
	red: "#f87171",
	text: "#f4f4f5",
	muted: "#a1a1aa",
	dim: "#7c8791",
};
const FONT = "Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif";
const MONO = "Menlo,ui-monospace,JetBrains Mono,Consolas,monospace";

// Two variants: the docs image (2x, 800 wide) and the social image (1200x630).
const VARIANTS = {
	main: { suffix: "", w: 800, scale: 2, margin: 40, font: 15, wrap: 72, capWrap: 100, capFont: 15 },
	og: {
		suffix: "-og",
		w: 1200,
		h: 630,
		scale: 1,
		margin: 60,
		font: 16,
		wrap: 100,
		capWrap: 130,
		capFont: 17,
	},
};
const CHAR_W = 0.602;
const LINE_H = 1.55;

const esc = (s) => s.replaceAll(/&/g, "&amp;").replaceAll(/</g, "&lt;").replaceAll(/>/g, "&gt;");

function wrapWords(text, max) {
	const out = [];
	let cur = "";
	for (const word of text.split(" ")) {
		if (cur && cur.length + 1 + word.length > max) {
			out.push(cur);
			cur = word;
		} else cur = cur ? cur + " " + word : word;
	}
	if (cur) out.push(cur);
	return out;
}

// Wrap a terminal line to max columns. Continuation lines keep the indent plus two spaces.
function wrapTerminal(line, max) {
	if (line.length <= max) return [line];
	const indent = line.match(/^\s*/)[0];
	const out = [];
	let cur = "";
	for (const word of line.trim().split(" ")) {
		const w = word;
		const lead = out.length === 0 ? indent : indent + "  ";
		if (cur && (lead + cur + " " + w).length > max) {
			out.push(lead + cur);
			cur = w;
		} else cur = cur ? cur + " " + w : w;
		while ((lead + cur).length > max) {
			out.push((lead + cur).slice(0, max));
			cur = cur.slice(max - lead.length);
		}
	}
	out.push((out.length === 0 ? indent : indent + "  ") + cur);
	return out;
}

// Color rules. A colored line also colors the more indented lines that follow it.
function classify(line) {
	if (/^\[\d+\]/.test(line)) return "label";
	if (/needs human approval|approval request/i.test(line)) return "amber";
	if (/(^\s*(newly denied|never used))|(\bremoved?\b)/.test(line)) return "red";
	if (/sent:|still allowed|verifies: true|extends .*: true/.test(line)) return "green";
	return "";
}

function tint(rows) {
	let inherit = "";
	let inheritIndent = -1;
	return rows.map((row) => {
		const indent = row.text.match(/^\s*/)[0].length;
		let kind = row.cont ? row.prevKind : classify(row.text);
		if (!kind && inheritIndent >= 0 && indent > inheritIndent && row.text.trim()) kind = inherit;
		if (!row.cont) {
			if (kind && classify(row.text)) {
				inherit = kind;
				inheritIndent = indent;
			} else if (indent <= inheritIndent) inheritIndent = -1;
		}
		return { ...row, kind };
	});
}

function labelHtml(text) {
	const m = text.match(/^(\s*)([A-Za-z][^:]{0,40}):(\s|$)(.*)$/);
	if (!m) return '<span class="t">' + esc(text) + "</span>";
	return (
		esc(m[1]) +
		'<span class="d">' +
		esc(m[2]) +
		":</span>" +
		'<span class="t">' +
		esc(m[3] + m[4]) +
		"</span>"
	);
}

function selectRows(output, ranges, wrap) {
	const src = output.replace(/\n$/, "").split("\n");
	const picked = ranges ?? [[1, src.length]];
	const rows = [];
	picked.forEach((r, i) => {
		if (i > 0) rows.push({ text: "...", ellipsis: true, orig: 0 });
		for (let n = r[0]; n <= r[1]; n++) {
			const parts = wrapTerminal(src[n - 1], wrap);
			let prevKind = "";
			parts.forEach((p, k) => {
				const kind = classify(src[n - 1]);
				prevKind = kind || prevKind;
				rows.push({ text: p, orig: n, cont: k > 0, prevKind: kind });
			});
		}
	});
	return rows;
}

function renderHtml(shot, output, v, ctx) {
	const rows = tint(selectRows(output, ctx.ranges, v.wrap));
	const lh = Math.round(v.font * LINE_H);
	const winW = v.w - v.margin * 2;
	const bodyPad = 18;
	const bar = 38;
	const promptRows = 1;
	const caretRows = v.h ? 0 : 1;
	const bodyH = bodyPad * 2 + (rows.length + promptRows + caretRows) * lh;
	const winH = bar + bodyH;
	const titleLines = wrapWords(shot.title, v.capWrap);
	const capLines = wrapWords(shot.caption, v.capWrap);
	const capBlock = 14 + titleLines.length * 26 + capLines.length * 23;
	const blockH = winH + 26 + capBlock;
	const topY = 74;
	let H = v.h ?? topY + blockH + 30;
	let startY = topY;
	if (v.h) {
		const free = v.h - topY - 30 - blockH;
		if (free < 0) throw new Error(shot.name + " og: content is " + -free + "px too tall");
		startY = topY + Math.floor(free / 2);
	}
	H = Math.round(H);
	const colors = { green: C.green, amber: C.amber, red: C.red, label: C.teal };
	const hi = new Set(shot.highlightLines ?? []);
	const body = rows
		.map((r) => {
			let html;
			if (r.ellipsis) html = '<span class="d">...</span>';
			else if (r.kind === "label") html = '<span class="lab">' + esc(r.text) + "</span>";
			else if (r.kind)
				html = '<span style="color:' + colors[r.kind] + '">' + esc(r.text) + "</span>";
			else html = labelHtml(r.text);
			const cls = hi.has(r.orig) ? "ln hi" : "ln";
			return '<div class="' + cls + '">' + html + "</div>";
		})
		.join("");
	const cmd =
		'<div class="ln"><span class="pr">$</span> <span class="t">' +
		esc(shot.command) +
		"</span></div>";
	const caret = '<div class="ln"><span class="pr">$</span> <span class="caret"></span></div>';
	const titleHtml = titleLines.map((l) => '<div class="ct">' + esc(l) + "</div>").join("");
	const capHtml = capLines.map((l) => '<div class="cc">' + esc(l) + "</div>").join("");
	const css = [
		"*{box-sizing:border-box}html,body{margin:0;width:" +
			v.w +
			"px;height:" +
			H +
			"px;background:" +
			C.bg +
			";overflow:hidden}",
		"body{position:relative;font-family:" + FONT + ";color:" + C.text + "}",
		".glow{position:absolute;inset:0;background:radial-gradient(60% 80% at 0% 0%,rgba(25,217,184,.28),transparent 70%),radial-gradient(40% 60% at 50% 0%,rgba(139,124,246,.22),transparent 70%),radial-gradient(45% 80% at 100% 0%,rgba(238,243,95,.18),transparent 70%)}",
		".grain{position:absolute;inset:0;opacity:.10}",
		".brand{position:absolute;left:" +
			v.margin +
			"px;top:22px;display:flex;align-items:center;gap:10px;font-size:17px;font-weight:600}",
		".url{position:absolute;right:" +
			v.margin +
			"px;top:26px;font:13px " +
			MONO +
			";color:" +
			C.lime +
			"}",
		".win{position:absolute;left:" +
			v.margin +
			"px;top:" +
			startY +
			"px;width:" +
			winW +
			"px;height:" +
			winH +
			"px;border-radius:12px;background:linear-gradient(180deg,#10171b,#0a0f12);border:1px solid #2f3f47;box-shadow:0 1px 0 rgba(255,255,255,.08) inset,0 2px 4px rgba(0,0,0,.5),0 18px 30px -6px rgba(0,0,0,.75),0 40px 80px -10px rgba(0,0,0,.8),0 0 60px rgba(25,217,184,.08);overflow:hidden}",
		".bar{height:" +
			bar +
			"px;display:flex;align-items:center;padding:0 16px;background:linear-gradient(180deg,#222d33,#182025);border-bottom:1px solid #2f3f47;position:relative}",
		".dot{width:12px;height:12px;border-radius:50%;margin-right:8px}",
		".bt{position:absolute;left:0;right:0;text-align:center;font:12px " +
			MONO +
			";color:" +
			C.dim +
			"}",
		".bd{padding:" + bodyPad + "px 22px;font:" + v.font + "px/" + lh + "px " + MONO + "}",
		".ln{white-space:pre;height:" + lh + "px;margin:0 -22px;padding:0 22px}",
		".hi{background:rgba(251,191,36,.10);box-shadow:inset 3px 0 0 " + C.amber + "}",
		".t{color:" +
			C.text +
			"}.d{color:" +
			C.dim +
			"}.pr{color:" +
			C.lime +
			"}.lab{color:" +
			C.teal +
			"}",
		".caret{display:inline-block;width:" +
			Math.round(v.font * CHAR_W) +
			"px;height:" +
			Math.round(v.font * 1.15) +
			"px;background:" +
			C.muted +
			";vertical-align:text-bottom;opacity:.8}",
		".cap{position:absolute;left:" +
			v.margin +
			"px;top:" +
			(startY + winH + 26) +
			"px;width:" +
			winW +
			"px}",
		".ct{font-size:" + (v.capFont + 3) + "px;line-height:26px;font-weight:650}",
		".cc{font-size:" + v.capFont + "px;line-height:23px;color:" + C.muted + "}",
		".cap .ct{margin-top:0}.cap .ct+.cc{margin-top:2px}",
	].join("");
	const mark =
		'<svg width="28" height="28" viewBox="0 0 28 28"><rect x=".75" y=".75" width="26.5" height="26.5" rx="7.5" fill="none" stroke="' +
		C.purple +
		'" stroke-width="2"/><rect x="7" y="7" width="14" height="14" rx="4" fill="none" stroke="' +
		C.purple +
		'" stroke-width="1.6"/><rect x="11" y="11" width="6" height="6" rx="1.8" fill="' +
		C.lime +
		'"/></svg>';
	const grain =
		'<svg class="grain" width="' +
		v.w +
		'" height="' +
		H +
		'"><filter id="n" x="0" y="0" width="100%" height="100%"><feTurbulence type="fractalNoise" baseFrequency=".85" numOctaves="2" seed="11" stitchTiles="stitch"/><feColorMatrix values="0 0 0 0 1  0 0 0 0 1  0 0 0 0 1  0 0 0 .7 0"/></filter><rect width="100%" height="100%" filter="url(#n)"/></svg>';
	const html =
		'<!doctype html><html><head><meta charset="utf-8"><style>' +
		css +
		"</style></head><body>" +
		'<div class="glow"></div>' +
		grain +
		'<div class="brand">' +
		mark +
		"<span>theAuth</span></div>" +
		'<div class="url">theauth.dev</div>' +
		'<div class="win"><div class="bar"><span class="dot" style="background:#ff5f57"></span><span class="dot" style="background:#febc2e"></span><span class="dot" style="background:#28c840"></span><span class="bt">theauth/sdk : zsh</span></div>' +
		'<div class="bd">' +
		cmd +
		body +
		(caretRows ? caret : "") +
		"</div></div>" +
		'<div class="cap">' +
		titleHtml +
		capHtml +
		"</div></body></html>";
	return { html, H };
}

function main() {
	const spec = JSON.parse(readFileSync(join(HERE, "terminal-shots.json"), "utf8"));
	rmSync(BUILD, { recursive: true, force: true });
	mkdirSync(BUILD, { recursive: true });
	mkdirSync(OUT, { recursive: true });
	const manifest = [];
	for (const shot of spec.shots) {
		const output = shot.outputFile ? readFileSync(join(HERE, shot.outputFile), "utf8") : shot.text;
		for (const [key, v] of Object.entries(VARIANTS)) {
			const ranges = key === "og" ? (shot.ogShowLines ?? shot.showLines) : shot.showLines;
			const { html, H } = renderHtml(shot, output, v, { ranges });
			const htmlPath = join(BUILD, shot.name + v.suffix + ".html");
			const png = join(BUILD, shot.name + v.suffix + ".png");
			writeFileSync(htmlPath, html);
			execFileSync(
				CHROME,
				[
					"--headless=new",
					"--disable-gpu",
					"--hide-scrollbars",
					"--force-device-scale-factor=" + v.scale,
					"--screenshot=" + png,
					"--window-size=" + v.w + "," + H,
					"file://" + htmlPath,
				],
				{ stdio: "ignore" },
			);
			const jpg = join(OUT, shot.name + v.suffix + ".jpg");
			execFileSync(MAGICK, [png, "-quality", "88", "-sampling-factor", "4:4:4", jpg]);
			const dims = execFileSync(MAGICK, ["identify", "-format", "%w %h", jpg], { encoding: "utf8" })
				.trim()
				.split(" ")
				.map(Number);
			manifest.push({
				file: "docs/images/terminal/" + shot.name + v.suffix + ".jpg",
				variant: key === "og" ? "social 1200x630" : "docs 2x",
				title: shot.title,
				alt: shot.alt,
				caption: shot.caption,
				source: shot.source,
				command: shot.command,
				width: dims[0],
				height: dims[1],
			});
		}
	}
	writeFileSync(
		join(OUT, "manifest.json"),
		JSON.stringify({ images: manifest }, null, "\t") + "\n",
	);
	rmSync(BUILD, { recursive: true, force: true });
	console.log("built " + manifest.length + " images");
}

main();
