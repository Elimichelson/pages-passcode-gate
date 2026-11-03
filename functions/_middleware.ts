// Example: copy this file to functions/_middleware.ts in your Pages project (and src/index.ts next to it),
// then set the PASSCODE secret in the Cloudflare dashboard. See README.md.
import { passcodeGate } from "../src/index";

export const onRequest = passcodeGate();
