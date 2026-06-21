import { kavachNextjs } from '@glinr/theauth-nextjs';
import { getKavach } from '@/lib/kavach';

const kavach = await getKavach();
const handlers = kavachNextjs(kavach);

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;
export const OPTIONS = handlers.OPTIONS;
