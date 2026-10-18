/** Caps how many calls run at once. Extra calls wait in a short queue; past that they fail fast. */
export interface ConcurrencyLimiter {
	run<T>(fn: () => Promise<T>): Promise<T>;
}

export function createConcurrencyLimiter(max: number, maxQueue: number): ConcurrencyLimiter {
	let active = 0;
	const queue: Array<() => void> = [];
	const next = (): void => {
		active--;
		queue.shift()?.();
	};
	return {
		run<T>(fn: () => Promise<T>): Promise<T> {
			return new Promise<T>((resolve, reject) => {
				const start = (): void => {
					active++;
					// The executor turns a synchronous throw from fn into a rejection of p.
					const p = new Promise<T>((res) => res(fn()));
					p.then(resolve, reject).finally(next);
				};
				if (active < max) start();
				else if (queue.length < maxQueue) queue.push(start);
				else reject(new Error("resolver busy"));
			});
		},
	};
}
