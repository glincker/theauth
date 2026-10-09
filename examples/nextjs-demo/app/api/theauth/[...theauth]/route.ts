import { theAuthNextjs } from '@glinr/theauth-nextjs';
import { getTheAuth } from '@/lib/theauth';

const auth = await getTheAuth();
const handlers = theAuthNextjs(auth, { basePath: '/api/theauth', allowUnauthenticated: true });

export const GET = handlers.GET;
export const POST = handlers.POST;
export const PATCH = handlers.PATCH;
export const DELETE = handlers.DELETE;
export const OPTIONS = handlers.OPTIONS;
