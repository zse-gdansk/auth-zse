import type { ReadonlyURLSearchParams } from "next/navigation";
import { OIDC_CONFIG } from "./config";
import LocalStorageTokenService from "./globals/client/LocalStorageTokenService";

export interface ValidationError {
    error: string;
    error_description: string;
}

export interface ValidatedParams {
    client_id: string;
    redirect_uri: string;
    response_type: string;
    scope: string;
    state: string;
    code_challenge: string;
    code_challenge_method: string;
}

export interface ValidationResult {
    valid: boolean;
    params?: ValidatedParams;
    error?: ValidationError;
}

/**
 * Validate OpenID Connect authorization request parameters from URL search params.
 *
 * Checks presence and basic validity of the required parameters: `client_id`, `redirect_uri`,
 * `response_type`, `scope`, `state`, `code_challenge`, and `code_challenge_method`.
 *
 * @param searchParams - The URL search parameters containing the authorization request values
 * @returns A ValidationResult where `valid` is `true` and `params` contains the parsed values
 *          when all checks pass; otherwise `valid` is `false` and `error` contains `error`
 *          and `error_description` explaining the failure.
 */
export function validateAuthorizationParams(searchParams: ReadonlyURLSearchParams): ValidationResult {
    const clientId = searchParams.get("client_id");
    const redirectUri = searchParams.get("redirect_uri");
    const responseType = searchParams.get("response_type");
    const scope = searchParams.get("scope");
    const state = searchParams.get("state");
    const codeChallenge = searchParams.get("code_challenge");
    const codeChallengeMethod = searchParams.get("code_challenge_method");

    if (!clientId) {
        return {
            valid: false,
            error: {
                error: "invalid_request",
                error_description: "Missing required parameter: client_id",
            },
        };
    }

    if (!redirectUri) {
        return {
            valid: false,
            error: {
                error: "invalid_request",
                error_description: "Missing required parameter: redirect_uri",
            },
        };
    }

    if (!responseType) {
        return {
            valid: false,
            error: {
                error: "invalid_request",
                error_description: "Missing required parameter: response_type",
            },
        };
    }

    if (responseType !== "code") {
        return {
            valid: false,
            error: {
                error: "unsupported_response_type",
                error_description: `Unsupported response_type: ${responseType}. Only 'code' is supported.`,
            },
        };
    }

    if (!scope) {
        return {
            valid: false,
            error: {
                error: "invalid_request",
                error_description: "Missing required parameter: scope",
            },
        };
    }

    if (!state) {
        return {
            valid: false,
            error: {
                error: "invalid_request",
                error_description: "Missing required parameter: state",
            },
        };
    }

    if (!codeChallenge) {
        return {
            valid: false,
            error: {
                error: "invalid_request",
                error_description: "Missing required parameter: code_challenge",
            },
        };
    }

    if (!codeChallengeMethod) {
        return {
            valid: false,
            error: {
                error: "invalid_request",
                error_description: "Missing required parameter: code_challenge_method",
            },
        };
    }

    if (codeChallengeMethod !== "s256" && codeChallengeMethod !== "plain") {
        return {
            valid: false,
            error: {
                error: "invalid_request",
                error_description: `Unsupported code_challenge_method: ${codeChallengeMethod}. Only 's256' and 'plain' are supported.`,
            },
        };
    }

    try {
        new URL(redirectUri);
    } catch {
        return {
            valid: false,
            error: {
                error: "invalid_request",
                error_description: "Invalid redirect_uri format",
            },
        };
    }

    return {
        valid: true,
        params: {
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: responseType,
            scope,
            state,
            code_challenge: codeChallenge,
            code_challenge_method: codeChallengeMethod,
        },
    };
}

/**
 * Construct a redirect URI that includes OIDC error parameters.
 *
 * @param redirectUri - The base redirect URI to append error parameters to.
 * @param error - The OIDC error object containing `error`, `error_description`, and optional `state`.
 * @returns The full redirect URI string with `error`, `error_description`, and optional `state` query parameters set.
 */
export function buildErrorRedirect(redirectUri: string, error: ValidationError & { state?: string }): string {
    const url = new URL(redirectUri);
    url.searchParams.set("error", error.error);
    url.searchParams.set("error_description", error.error_description);
    if (error.state) {
        url.searchParams.set("state", error.state);
    }
    return url.toString();
}

/**
 * Constructs a redirect URL containing the authorization code and optional state.
 *
 * @param redirectUri - The destination redirect URI (must be a valid absolute URL) to which the parameters will be appended
 * @param code - The authorization code to set as the `code` query parameter
 * @param state - Optional `state` value to include as the `state` query parameter
 * @returns The full redirect URI string with `code` and, if provided, `state` added as query parameters
 */
export function buildSuccessRedirect(redirectUri: string, code: string, state?: string): string {
    const url = new URL(redirectUri);
    url.searchParams.set("code", code);
    if (state) {
        url.searchParams.set("state", state);
    }
    return url.toString();
}

/**
 * Generates a random code verifier for PKCE
 */
export function generateCodeVerifier(length: number = 64): string {
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let result = "";
    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);
    for (let i = 0; i < length; i++) {
        result += charset[randomValues[i] % charset.length];
    }
    return result;
}

/**
 * Generates the PKCE code challenge for a given code verifier using SHA-256.
 *
 * @param codeVerifier - The PKCE code verifier string
 * @returns The Base64URL-encoded SHA-256 digest of `codeVerifier`, without padding
 */
export async function generateCodeChallenge(codeVerifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hash = await crypto.subtle.digest("SHA-256", data);

    // Convert buffer to Base64URL
    return btoa(String.fromCharCode(...new Uint8Array(hash)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

/**
 * Starts the OIDC Authorization Code flow with PKCE by generating state and a code verifier, persisting them, and redirecting the browser to the authorization endpoint.
 *
 * The function creates a PKCE code challenge from the verifier, stores the state and verifier via LocalStorageTokenService, builds authorization parameters from OIDC_CONFIG, and navigates to the authorize endpoint.
 */
export async function loginWithRedirect(): Promise<void> {
    const state = generateCodeVerifier(32);
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    LocalStorageTokenService.setOidcState(state);
    LocalStorageTokenService.setOidcCodeVerifier(codeVerifier);

    const params = new URLSearchParams({
        client_id: OIDC_CONFIG.client_id,
        redirect_uri: OIDC_CONFIG.redirect_uri,
        response_type: OIDC_CONFIG.response_type,
        scope: OIDC_CONFIG.scope,
        state: state,
        code_challenge: codeChallenge,
        code_challenge_method: "s256",
    });

    redirectToAuthorize(params.toString());
}

/**
 * Redirects the user to the authorization endpoint with the provided OIDC parameters.
 *
 * Decodes the provided parameters string, constructs a URL to the local `/authorize` endpoint,
 * appends the parameters, and navigates the window to that URL. Falls back to a simple
 * string append if URL construction fails.
 *
 * @param oidcParams - URL-encoded OIDC query parameters
 */
export function redirectToAuthorize(oidcParams: string): void {
    try {
        const decoded = decodeURIComponent(oidcParams);
        const params = new URLSearchParams(decoded);
        const authorizeUrl = new URL("/authorize", window.location.origin);
        params.forEach((value, key) => {
            authorizeUrl.searchParams.set(key, value);
        });
        window.location.href = authorizeUrl.toString();
    } catch {
        window.location.href = `/authorize?${oidcParams}`;
    }
}
