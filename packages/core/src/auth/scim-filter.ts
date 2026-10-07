/**
 * SCIM 2.0 filter parser and evaluator (RFC 7644 §3.4.2.2).
 *
 * Builds a filter AST from the grammar:
 *
 *   FILTER    = attrExp / logExp / valuePath / "not" "(" FILTER ")"
 *   valuePath = attrPath "[" valFilter "]"
 *   attrExp   = attrPath SP "pr"
 *             / attrPath SP compareOp SP compValue
 *   logExp    = FILTER SP ("and" / "or") SP FILTER
 *   compareOp = eq / ne / co / sw / ew / gt / lt / ge / le
 *   compValue = false / null / true / number / string
 *
 * The evaluator walks the AST against a plain JS object that represents a
 * SCIM resource. String equality is case-insensitive per §3.4.2.2. Date
 * comparisons work on ISO-8601 strings via lexical compare.
 */

export type CompOp = "eq" | "ne" | "co" | "sw" | "ew" | "gt" | "lt" | "ge" | "le";

export interface AttrPath {
	schemaUrn?: string;
	path: string[];
}

export type FilterValue = string | number | boolean | null;

export type FilterAst =
	| { kind: "and"; left: FilterAst; right: FilterAst }
	| { kind: "or"; left: FilterAst; right: FilterAst }
	| { kind: "not"; inner: FilterAst }
	| { kind: "cmp"; attr: AttrPath; op: CompOp; value: FilterValue }
	| { kind: "pr"; attr: AttrPath }
	| { kind: "valuePath"; attr: AttrPath; inner: FilterAst };

export class ScimFilterError extends Error {
	public readonly scimType = "invalidFilter";
	constructor(message: string) {
		super(message);
		this.name = "ScimFilterError";
	}
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

type TokenKind =
	| "lparen"
	| "rparen"
	| "lbracket"
	| "rbracket"
	| "word"
	| "string"
	| "number"
	| "boolean"
	| "null"
	| "eof";

interface Token {
	kind: TokenKind;
	value: string;
	start: number;
}

const WORD_RE = /[A-Za-z0-9_\-:.]/;

function tokenize(input: string): Token[] {
	const tokens: Token[] = [];
	let i = 0;
	const n = input.length;

	while (i < n) {
		const c = input[i] as string;

		if (c === " " || c === "\t" || c === "\n" || c === "\r") {
			i += 1;
			continue;
		}

		if (c === "(") {
			tokens.push({ kind: "lparen", value: "(", start: i });
			i += 1;
			continue;
		}

		if (c === ")") {
			tokens.push({ kind: "rparen", value: ")", start: i });
			i += 1;
			continue;
		}

		if (c === "[") {
			tokens.push({ kind: "lbracket", value: "[", start: i });
			i += 1;
			continue;
		}

		if (c === "]") {
			tokens.push({ kind: "rbracket", value: "]", start: i });
			i += 1;
			continue;
		}

		if (c === '"') {
			const start = i;
			i += 1;
			let value = "";
			while (i < n && input[i] !== '"') {
				if (input[i] === "\\" && i + 1 < n) {
					const next = input[i + 1] as string;
					if (next === '"' || next === "\\" || next === "/") {
						value += next;
						i += 2;
						continue;
					}
					if (next === "t") {
						value += "\t";
						i += 2;
						continue;
					}
					if (next === "n") {
						value += "\n";
						i += 2;
						continue;
					}
					if (next === "r") {
						value += "\r";
						i += 2;
						continue;
					}
					value += input[i];
					i += 1;
					continue;
				}
				value += input[i];
				i += 1;
			}
			if (i >= n) {
				throw new ScimFilterError(`Unterminated string literal at position ${start}`);
			}
			i += 1; // skip closing quote
			tokens.push({ kind: "string", value, start });
			continue;
		}

		if (c === "-" || (c >= "0" && c <= "9")) {
			const start = i;
			let raw = "";
			if (c === "-") {
				raw += "-";
				i += 1;
			}
			while (i < n && /[0-9.eE+-]/.test(input[i] as string)) {
				raw += input[i];
				i += 1;
			}
			if (raw === "" || raw === "-" || Number.isNaN(Number(raw))) {
				throw new ScimFilterError(`Invalid number literal at position ${start}`);
			}
			tokens.push({ kind: "number", value: raw, start });
			continue;
		}

		if (WORD_RE.test(c)) {
			const start = i;
			let raw = "";
			while (i < n && WORD_RE.test(input[i] as string)) {
				raw += input[i];
				i += 1;
			}
			const lower = raw.toLowerCase();
			if (lower === "true" || lower === "false") {
				tokens.push({ kind: "boolean", value: lower, start });
				continue;
			}
			if (lower === "null") {
				tokens.push({ kind: "null", value: "null", start });
				continue;
			}
			tokens.push({ kind: "word", value: raw, start });
			continue;
		}

		throw new ScimFilterError(`Unexpected character "${c}" at position ${i}`);
	}

	tokens.push({ kind: "eof", value: "", start: n });
	return tokens;
}

// ---------------------------------------------------------------------------
// Parser (recursive descent with precedence: not > and > or)
// ---------------------------------------------------------------------------

const COMP_OPS = new Set<string>(["eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le"]);

/**
 * Parse a SCIM filter expression into an AST.
 *
 * @throws ScimFilterError when the input does not conform to RFC 7644 §3.4.2.2.
 */
export function parseFilter(input: string): FilterAst {
	const tokens = tokenize(input);
	let pos = 0;

	function peek(): Token {
		return tokens[pos] as Token;
	}

	function eat(): Token {
		const t = tokens[pos] as Token;
		pos += 1;
		return t;
	}

	function expectKind(kind: TokenKind): Token {
		const t = peek();
		if (t.kind !== kind) {
			throw new ScimFilterError(`Expected ${kind} at position ${t.start}, got ${t.kind}`);
		}
		return eat();
	}

	function matchWord(word: string): boolean {
		const t = peek();
		return t.kind === "word" && t.value.toLowerCase() === word;
	}

	function parseAttrPath(): AttrPath {
		const t = peek();
		if (t.kind !== "word") {
			throw new ScimFilterError(`Expected attribute path at position ${t.start}`);
		}
		eat();
		const raw = t.value;
		// Split on the last ':' only if the first part looks like a URN
		const colonIndex = raw.lastIndexOf(":");
		let schemaUrn: string | undefined;
		let tail = raw;
		if (colonIndex > 0 && raw.startsWith("urn:")) {
			schemaUrn = raw.slice(0, colonIndex);
			tail = raw.slice(colonIndex + 1);
		}
		const parts = tail.split(".").filter((part) => part.length > 0);
		if (parts.length === 0) {
			throw new ScimFilterError(`Empty attribute path at position ${t.start}`);
		}
		return { schemaUrn, path: parts };
	}

	function parseCompValue(): FilterValue {
		const t = eat();
		if (t.kind === "string") return t.value;
		if (t.kind === "number") return Number(t.value);
		if (t.kind === "boolean") return t.value === "true";
		if (t.kind === "null") return null;
		throw new ScimFilterError(`Expected comparison value at position ${t.start}, got ${t.kind}`);
	}

	function parsePrimary(): FilterAst {
		if (matchWord("not")) {
			eat();
			expectKind("lparen");
			const inner = parseOr();
			expectKind("rparen");
			return { kind: "not", inner };
		}

		if (peek().kind === "lparen") {
			eat();
			const inner = parseOr();
			expectKind("rparen");
			return inner;
		}

		const attr = parseAttrPath();

		// valuePath: attr[filter]
		if (peek().kind === "lbracket") {
			eat();
			const inner = parseOr();
			expectKind("rbracket");
			return { kind: "valuePath", attr, inner };
		}

		const opTok = peek();
		if (opTok.kind !== "word") {
			throw new ScimFilterError(`Expected operator at position ${opTok.start}`);
		}

		const op = opTok.value.toLowerCase();
		if (op === "pr") {
			eat();
			return { kind: "pr", attr };
		}
		if (COMP_OPS.has(op)) {
			eat();
			const value = parseCompValue();
			return { kind: "cmp", attr, op: op as CompOp, value };
		}
		throw new ScimFilterError(`Unknown operator "${opTok.value}" at position ${opTok.start}`);
	}

	function parseAnd(): FilterAst {
		let left = parsePrimary();
		while (matchWord("and")) {
			eat();
			const right = parsePrimary();
			left = { kind: "and", left, right };
		}
		return left;
	}

	function parseOr(): FilterAst {
		let left = parseAnd();
		while (matchWord("or")) {
			eat();
			const right = parseAnd();
			left = { kind: "or", left, right };
		}
		return left;
	}

	const ast = parseOr();
	if (peek().kind !== "eof") {
		throw new ScimFilterError(`Unexpected trailing input at position ${peek().start}`);
	}
	return ast;
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

type Resource = Record<string, unknown>;

/** Evaluate a filter AST against a single SCIM resource. */
export function evaluateFilter(ast: FilterAst, resource: Resource): boolean {
	switch (ast.kind) {
		case "and":
			return evaluateFilter(ast.left, resource) && evaluateFilter(ast.right, resource);
		case "or":
			return evaluateFilter(ast.left, resource) || evaluateFilter(ast.right, resource);
		case "not":
			return !evaluateFilter(ast.inner, resource);
		case "pr":
			return hasPresent(readPath(resource, ast.attr));
		case "cmp":
			return compareAny(readPath(resource, ast.attr), ast.op, ast.value);
		case "valuePath":
			return evaluateValuePath(ast, resource);
	}
}

/** Convenience — parse and evaluate in one shot. */
export function matchFilter(filter: string, resource: Resource): boolean {
	return evaluateFilter(parseFilter(filter), resource);
}

function evaluateValuePath(
	node: Extract<FilterAst, { kind: "valuePath" }>,
	resource: Resource,
): boolean {
	const value = readPath(resource, node.attr);
	if (value === undefined || value === null) return false;
	const items = Array.isArray(value) ? value : [value];
	for (const item of items) {
		if (item && typeof item === "object") {
			if (evaluateFilter(node.inner, item as Resource)) return true;
		}
	}
	return false;
}

function readPath(resource: Resource, attr: AttrPath): unknown {
	let current: unknown = resource;
	if (attr.schemaUrn && attr.schemaUrn !== "urn:ietf:params:scim:schemas:core:2.0:User") {
		// Schema extension lives under the URN key by convention (RFC 7643 §4.3).
		if (current && typeof current === "object") {
			const record = current as Record<string, unknown>;
			current = record[attr.schemaUrn];
		}
	}
	for (const segment of attr.path) {
		if (current === undefined || current === null) return undefined;
		if (Array.isArray(current)) {
			// Walking into an array without a value-path collects sub-values.
			const collected: unknown[] = [];
			for (const item of current) {
				if (item && typeof item === "object") {
					const sub = (item as Record<string, unknown>)[segment];
					if (sub !== undefined) collected.push(sub);
				}
			}
			current = collected.length > 0 ? collected : undefined;
			continue;
		}
		if (typeof current !== "object") return undefined;
		current = (current as Record<string, unknown>)[segment];
	}
	return current;
}

function hasPresent(value: unknown): boolean {
	if (value === undefined || value === null) return false;
	if (typeof value === "string") return value.length > 0;
	if (Array.isArray(value)) return value.length > 0;
	if (typeof value === "object") return Object.keys(value as object).length > 0;
	return true;
}

function compareAny(raw: unknown, op: CompOp, target: FilterValue): boolean {
	if (Array.isArray(raw)) {
		return raw.some((item) => compareScalar(item, op, target));
	}
	return compareScalar(raw, op, target);
}

function compareScalar(raw: unknown, op: CompOp, target: FilterValue): boolean {
	if (raw === undefined) return false;

	if (typeof raw === "string" && typeof target === "string") {
		return compareString(raw, op, target);
	}
	if (typeof raw === "number" && typeof target === "number") {
		return compareNumber(raw, op, target);
	}
	if (typeof raw === "boolean" && typeof target === "boolean") {
		if (op === "eq") return raw === target;
		if (op === "ne") return raw !== target;
		return false;
	}
	if (raw === null) {
		if (op === "eq") return target === null;
		if (op === "ne") return target !== null;
		return false;
	}
	// Type mismatch — only eq/ne are meaningful.
	if (op === "ne") return true;
	return false;
}

function compareString(raw: string, op: CompOp, target: string): boolean {
	const a = raw.toLowerCase();
	const b = target.toLowerCase();
	switch (op) {
		case "eq":
			return a === b;
		case "ne":
			return a !== b;
		case "co":
			return a.includes(b);
		case "sw":
			return a.startsWith(b);
		case "ew":
			return a.endsWith(b);
		case "gt":
			return a > b;
		case "ge":
			return a >= b;
		case "lt":
			return a < b;
		case "le":
			return a <= b;
	}
}

function compareNumber(raw: number, op: CompOp, target: number): boolean {
	switch (op) {
		case "eq":
			return raw === target;
		case "ne":
			return raw !== target;
		case "gt":
			return raw > target;
		case "ge":
			return raw >= target;
		case "lt":
			return raw < target;
		case "le":
			return raw <= target;
		case "co":
		case "sw":
		case "ew":
			return false;
	}
}
