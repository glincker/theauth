import { kavachNextjs } from "@kavachos/nextjs";
import { getKavach } from "@/lib/kavach";

const { GET, POST } = kavachNextjs(getKavach);

export { GET, POST };
