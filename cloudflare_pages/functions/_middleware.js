import { Buffer } from "node:buffer";

const encoder = new TextEncoder();

/**
 * Protect against timing attacks by safely comparing values using `timingSafeEqual`.
 * Refer to https://developers.cloudflare.com/workers/runtime-apis/web-crypto/#timingsafeequal for more details
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function timingSafeEqual(a, b) {
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);

  if (aBytes.byteLength !== bBytes.byteLength) {
    // Strings must be the same length in order to compare
    // with crypto.subtle.timingSafeEqual
    return false;
  }

  return crypto.subtle.timingSafeEqual(aBytes, bBytes);
}

function promptToLogin() {
  return new Response("You need to login.", {
    status: 401,
    headers: {
      // Prompts the user for credentials.
      "WWW-Authenticate": 'Basic realm="myrealm", charset="UTF-8"',
    },
  });
}

function authHandling(context) {
  // You will need an admin password. This should be
  // attached to your Worker as an encrypted secret.
  // Refer to https://developers.cloudflare.com/workers/configuration/secrets/
  const password = context.env.PASSWORD;
  if (!password) {
    throw new Error("PASSWORD secret is not set");
  }

  const url = new URL(context.request.url);
  if (url.pathname === "/logout") {
      // Invalidate the "Authorization" header by returning a HTTP 401.
      // We do not send a "WWW-Authenticate" header, as this would trigger
      // a popup in the browser, immediately asking for credentials again.
      return new Response("Logged out.", { status: 401 });
  }
  // The "Authorization" header is sent when authenticated.
  const authorization = context.request.headers.get("Authorization");
  if (!authorization) {
    return promptToLogin();
  }
  const [scheme, encoded] = authorization.split(" ");

  // The Authorization header must start with Basic, followed by a space.
  if (!encoded || scheme !== "Basic") {
    return new Response("Malformed authorization header.", {
      status: 400,
    });
  }

  const credentials = Buffer.from(encoded, "base64").toString();
  if (!timingSafeEqual(credentials, password)) {
    return promptToLogin();
  }
  return context.next();
}

export const onRequest = [authHandling];
