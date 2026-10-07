import { theAuthNextjs } from "@glinr/theauth-nextjs";
import { getTheAuth } from "@/lib/theauth";

const { GET, POST } = theAuthNextjs(getTheAuth);

export { GET, POST };
