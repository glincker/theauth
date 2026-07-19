import { theAuthNextjs } from '@glinr/theauth-nextjs';
import { getKavach } from '@/lib/kavach';

const auth = await getKavach();
const handlers = theAuthNextjs(auth, { basePath: '/api/theauth' });

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;
export const OPTIONS = handlers.OPTIONS;
