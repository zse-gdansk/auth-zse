"use client";

import { useEffect, useRef, useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { exchangeToken } from "@/authly/lib/api";
import LocalStorageTokenService from "@/authly/lib/globals/client/LocalStorageTokenService";
import { OIDC_CONFIG } from "@/authly/lib/config";
import AuthorizeLayout from "@/authly/components/authorize/AuthorizeLayout";
import Button from "@/authly/components/ui/Button";

/**
 * Processes the OAuth/OIDC authorization callback, performs state validation and token exchange, and renders authentication status UI.
 *
 * This component runs its callback handling once on mount: it validates the `state` query parameter against the stored OIDC state, handles `error` query parameters, exchanges an authorization `code` for tokens using the stored code verifier, stores the access token on success, clears OIDC transient values, and navigates to the dashboard. If any validation or exchange step fails it displays an error screen with a button to return to the login page.
 *
 * @returns A JSX element that shows a centered "Authenticating..." progress UI while processing or an error screen with a "Back to Login" button when an error occurs.
 */
function CallbackPageContent() {
    const router = useRouter();
    const searchParams = useSearchParams();
    const [error, setError] = useState<string | null>(null);
    const processedRef = useRef(false);

    useEffect(() => {
        if (processedRef.current) return;
        processedRef.current = true;

        const handleCallback = async () => {
            const code = searchParams.get("code");
            const stateParam = searchParams.get("state");
            const errorParam = searchParams.get("error");
            const errorDescription = searchParams.get("error_description");

            const storedState = LocalStorageTokenService.oidcState;
            if (!stateParam || !storedState || stateParam !== storedState) {
                setError("Walidacja stanu nieudana. Spróbuj ponownie zalogować się.");
                return;
            }

            if (errorParam) {
                setError(`${errorParam}: ${errorDescription || "Unknown error"}`);
                return;
            }

            if (!code) {
                setError("Nie znaleziono kodu autoryzacyjnego w URL.");
                return;
            }

            const codeVerifier = LocalStorageTokenService.oidcCodeVerifier;
            if (!codeVerifier) {
                setError("Nie znaleziono verifier kodu. Spróbuj ponownie zalogować się.");
                return;
            }

            try {
                const response = await exchangeToken({
                    grant_type: "authorization_code",
                    code: code,
                    redirect_uri: OIDC_CONFIG.redirect_uri,
                    client_id: OIDC_CONFIG.client_id,
                    code_verifier: codeVerifier,
                });

                if ("error" in response) {
                    setError(`${response.error}: ${response.error_description}`);
                } else {
                    LocalStorageTokenService.setAccessToken(response.access_token);
                    LocalStorageTokenService.setOidcCodeVerifier("");
                    LocalStorageTokenService.setOidcState("");

                    router.push("/dashboard");
                }
            } catch (err) {
                console.error("Token exchange failed", err);
                setError("Wystąpił nieoczekiwany błąd podczas wymiany tokenów.");
            }
        };

        handleCallback();
    }, [router, searchParams]);

    if (error) {
        return (
            <AuthorizeLayout>
                <div className="space-y-6">
                    <div className="space-y-1">
                        <h2 className="text-xl font-semibold text-red-600">Logowanie nieudane</h2>
                        <p className="text-sm text-gray-500">{error}</p>
                    </div>

                    <div className="pt-1">
                        <Button fullWidth variant="primary" onClick={() => router.push("/auth/login")}>
                            Wróć do logowania
                        </Button>
                    </div>
                </div>
            </AuthorizeLayout>
        );
    }

    return (
        <AuthorizeLayout>
            <div className="flex flex-col items-center justify-center py-12 space-y-4">
                <div className="h-8 w-8 animate-spin rounded-full border-2 border-gray-900 border-t-transparent"></div>
                <p className="text-sm text-gray-500">Autoryzowanie...</p>
            </div>
        </AuthorizeLayout>
    );
}

/**
 * Renders the OAuth/OIDC callback page with a Suspense boundary and loading fallback while authentication is processed.
 *
 * @returns The page's JSX element containing a Suspense wrapper with a loading fallback and the callback content.
 */
export default function CallbackPage() {
    return (
        <Suspense
            fallback={
                <div className="min-h-screen w-full flex items-center justify-center bg-gray-50">
                    <div className="text-gray-500">Ładowanie...</div>
                </div>
            }
        >
            <CallbackPageContent />
        </Suspense>
    );
}
