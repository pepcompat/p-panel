import { API_BASE, API_MOCK, CLIENT_VERSION } from '../config';
import { createApiClient } from './client';

let authFailureHandler: () => void = () => {};
export function setAuthFailureHandler(fn: () => void) {
  authFailureHandler = fn;
}

/** In mock mode requests are served by an in-process adapter that returns contract-shaped envelopes. */
const mockFetch: typeof fetch = (input, init) => import('@/mocks/adapter').then((m) => m.mockFetch(input, init));

export const api = createApiClient({
  baseUrl: API_BASE,
  clientVersion: CLIENT_VERSION,
  fetch: API_MOCK ? mockFetch : undefined,
  onAuthFailure: () => authFailureHandler(),
});

export { ApiError, isApiError, toApiError } from './errors';
export { tokenStore } from './token-store';
