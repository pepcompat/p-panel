/**
 * Access token lives in memory only (never localStorage / URL). The refresh token is an
 * HttpOnly cookie managed by the API (`ppanel_rt`, Path=/api/v1/auth) and is invisible to JS.
 */
type Listener = (token: string | null) => void;

let accessToken: string | null = null;
const listeners = new Set<Listener>();

export const tokenStore = {
  get: () => accessToken,
  set(token: string | null) {
    accessToken = token;
    listeners.forEach((l) => l(token));
  },
  subscribe(l: Listener) {
    listeners.add(l);
    return () => listeners.delete(l);
  },
};
