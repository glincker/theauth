import { kavachNextjs } from "@theauth/nextjs";
import { getKavach } from "@/lib/kavach";

const { GET, POST } = kavachNextjs(getKavach);

export { GET, POST };
