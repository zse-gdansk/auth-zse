"use client";

import { useSearchParams, useRouter } from "next/navigation";
import { Suspense, useState, useEffect, useCallback } from "react";
import Input from "@/authly/components/ui/Input";
import Button from "@/authly/components/ui/Button";
import { isApiError, checkIdPSession } from "@/authly/lib/api";
import { loginRequestSchema, type LoginRequest } from "@/authly/lib/schemas/auth/login";
import { generateCodeVerifier, generateCodeChallenge } from "@/authly/lib/oidc";
import LocalStorageTokenService from "@/authly/lib/globals/client/LocalStorageTokenService";
import { useLogin } from "@/authly/lib/hooks/useAuth";

type LoginFormData = {
    username: string;
    password: string;
};

/**
 * Render the login UI, manage form state and validation, perform authentication, and handle post-auth redirect behavior.
 *
 * If an IdP session exists or sign-in succeeds and an `oidc_params` query parameter is present, redirects to `/authorize`
 * (adding PKCE parameters when missing); otherwise navigates to the application root.
 *
 * @returns The login page content as a React element
 */
function LoginPageContent() {
    const searchParams = useSearchParams();
    const router = useRouter();
    const [formData, setFormData] = useState<LoginFormData>({
        username: "",
        password: "",
    });
    const [errors, setErrors] = useState<Partial<Record<keyof LoginFormData, string>>>({});
    const [apiError, setApiError] = useState<string | null>(null);
    const [isCheckingSession, setIsCheckingSession] = useState(true);
    const [isRedirecting, setIsRedirecting] = useState(false);

    const loginMutation = useLogin();

    const performRedirect = useCallback(async () => {
        const oidcParams = searchParams.get("oidc_params");
        if (oidcParams) {
            const handleOidcRedirect = async () => {
                try {
                    const decoded = decodeURIComponent(oidcParams);
                    const params = new URLSearchParams(decoded);

                    if (!params.has("code_challenge")) {
                        const verifier = generateCodeVerifier();
                        const challenge = await generateCodeChallenge(verifier);

                        params.set("code_challenge", challenge);
                        params.set("code_challenge_method", "s256");

                        LocalStorageTokenService.setOidcCodeVerifier(verifier);
                    }

                    const authorizeUrl = new URL("/authorize", window.location.origin);
                    params.forEach((value, key) => {
                        authorizeUrl.searchParams.set(key, value);
                    });
                    router.push(authorizeUrl.toString());
                } catch (error) {
                    console.error("Failed to process OIDC parameters:", error);
                    setApiError(
                        "Nie udało się przetworzyć parametrów logowania. Spróbuj ponownie lub wróć do strony głównej.",
                    );
                    LocalStorageTokenService.setOidcCodeVerifier("");
                    setIsCheckingSession(false);
                    setIsRedirecting(false);
                }
            };
            await handleOidcRedirect();
        } else {
            router.push("/");
        }
    }, [searchParams, router]);

    useEffect(() => {
        const checkSession = async () => {
            const hasSession = await checkIdPSession();
            if (hasSession) {
                await performRedirect();
            } else {
                setIsCheckingSession(false);
            }
        };
        checkSession();
    }, [performRedirect]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setErrors({});
        setApiError(null);

        const validation = loginRequestSchema.safeParse(formData);
        if (!validation.success) {
            const fieldErrors: Partial<Record<keyof LoginFormData, string>> = {};
            validation.error.issues.forEach((issue) => {
                const field = issue.path[0] as keyof LoginFormData;
                if (field) {
                    fieldErrors[field] = issue.message;
                }
            });
            setErrors(fieldErrors);
            return;
        }

        const requestData: LoginRequest = {
            username: formData.username,
            password: formData.password,
        };

        loginMutation.mutate(requestData, {
            onSuccess: async (response) => {
                if (response.success) {
                    setIsRedirecting(true);
                    try {
                        await performRedirect();
                    } catch (error) {
                        console.error("Redirect failed:", error);
                        setIsRedirecting(false);
                    }
                } else {
                    setApiError(response.error || "Logowanie nieudane");
                }
            },
            onError: (err) => {
                if (isApiError(err)) {
                    setApiError(err.error_description || err.error);
                } else if (err instanceof Error) {
                    setApiError(err.message);
                } else {
                    setApiError("Wystąpił błąd");
                }
            },
        });
    };

    const updateField = (field: keyof LoginFormData, value: string) => {
        setFormData((prev) => ({ ...prev, [field]: value }));
        if (errors[field]) {
            setErrors((prev) => {
                const newErrors = { ...prev };
                delete newErrors[field];
                return newErrors;
            });
        }
    };

    const isLoading = loginMutation.isPending || isRedirecting;

    if (isCheckingSession) {
        return (
            <div className="flex items-center justify-center py-12">
                <div className="text-gray-500">Ładowanie...</div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="space-y-1">
                <h2 className="text-xl font-semibold text-gray-900">Zaloguj się</h2>
                <p className="text-sm text-gray-500">Wprowadź swoje dane, aby kontynuować</p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-5">
                <Input
                    label="Nazwa użytkownika"
                    type="text"
                    placeholder="nazwa użytkownika"
                    value={formData.username}
                    onChange={(e) => updateField("username", e.target.value)}
                    required
                    disabled={isLoading}
                    error={errors.username}
                />

                <Input
                    label="Hasło"
                    type="password"
                    placeholder="••••••••"
                    value={formData.password}
                    onChange={(e) => updateField("password", e.target.value)}
                    required
                    disabled={isLoading}
                    error={errors.password}
                />

                {apiError && <p className="text-xs font-medium text-red-500">{apiError}</p>}

                <div className="pt-1">
                    <Button fullWidth variant="primary" type="submit" disabled={isLoading}>
                        {isLoading ? (isRedirecting ? "Przekierowywanie..." : "Logowanie...") : "Zaloguj się"}
                    </Button>
                </div>
            </form>

            <div className="pt-2 border-t border-gray-200">
                <p className="text-center text-sm text-gray-500 mt-2">
                    Nie masz konta?{" "}
                    {(() => {
                        const oidcParams = searchParams.get("oidc_params");
                        return (
                            <a
                                href={`/auth/register${oidcParams ? `?oidc_params=${encodeURIComponent(oidcParams)}` : ""}`}
                                className="text-gray-900 hover:text-black font-medium underline underline-offset-4 transition-colors duration-200"
                            >
                                Zarejestruj się
                            </a>
                        );
                    })()}
                </p>
            </div>
        </div>
    );
}

/**
 * Page wrapper that renders the login UI inside a Suspense boundary.
 *
 * @returns The login page UI wrapped in a Suspense boundary. While the login content is resolving, displays a full-screen loading fallback.
 */
export default function LoginPage() {
    return (
        <Suspense
            fallback={
                <div className="min-h-screen w-full flex items-center justify-center bg-gray-50">
                    <div className="text-gray-500">Ładowanie...</div>
                </div>
            }
        >
            <LoginPageContent />
        </Suspense>
    );
}
