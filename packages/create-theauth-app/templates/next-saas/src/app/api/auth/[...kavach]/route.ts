import { kavachNextjs } from "@glinr/theauth-nextjs";
import { getKavach } from "@/lib/kavach";

const { GET, POST } = kavachNextjs(getKavach);

export { GET, POST };
