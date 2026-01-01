"use client";

import { useSearchParams, useRouter } from "next/navigation";
import { Suspense, useState, useEffect, useRef } from "react";
import Input from "@/authly/components/ui/Input";
import Button from "@/authly/components/ui/Button";
import { isApiError } from "@/authly/lib/api";
import { registerFormSchema, registerRequestSchema, type RegisterFormData } from "@/authly/lib/schemas/auth/register";
import { generateCodeVerifier, generateCodeChallenge } from "@/authly/lib/oidc";
import LocalStorageTokenService from "@/authly/lib/globals/client/LocalStorageTokenService";
import { useRegister, useMe } from "@/authly/lib/hooks/useAuth";
import { CheckCircle } from "lucide-react";

/**
 * Renders the registration page UI, manages form state and validation, submits registration requests, and redirects on success or when already authenticated.
 *
 * The component validates input using the registration schema, surfaces per-field and API errors, disables inputs while the registration mutation is pending, and preserves `oidc_params` through redirect flows when present.
 *
 * @returns The registration page content as a React element.
 */
function RegisterPageContent() {
    const searchParams = useSearchParams();
    const router = useRouter();
    const [formData, setFormData] = useState<RegisterFormData>({
        first_name: "",
        last_name: "",
        email: "",
        username: "",
        password: "",
        confirmPassword: "",
    });
    const [errors, setErrors] = useState<Partial<Record<keyof RegisterFormData, string>>>({});
    const [apiError, setApiError] = useState<string | null>(null);
    const [successMessage, setSuccessMessage] = useState<string | null>(null);
    const isRedirectingRef = useRef(false);

    const { data: meResponse, isLoading: isCheckingAuth } = useMe();
    const registerMutation = useRegister();

    useEffect(() => {
        if (meResponse?.success && !successMessage) {
            if (isRedirectingRef.current) return;

            const oidcParams = searchParams.get("oidc_params");
            if (oidcParams) {
                isRedirectingRef.current = true;
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
                        router.push("/authorize?" + oidcParams);
                    }
                };
                handleOidcRedirect().catch((error) => {
                    console.error("OIDC redirect failed:", error);
                    isRedirectingRef.current = false;
                });
            } else {
                router.push("/");
            }
        }
    }, [meResponse, router, searchParams, successMessage]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setErrors({});
        setApiError(null);

        const validation = registerFormSchema.safeParse(formData);
        if (!validation.success) {
            const fieldErrors: Partial<Record<keyof RegisterFormData, string>> = {};
            validation.error.issues.forEach((issue) => {
                const field = issue.path[0] as keyof RegisterFormData;
                if (field) {
                    fieldErrors[field] = issue.message;
                }
            });
            setErrors(fieldErrors);
            return;
        }

        const requestValidation = registerRequestSchema.safeParse({
            first_name: formData.first_name || undefined,
            last_name: formData.last_name || undefined,
            email: formData.email || undefined,
            username: formData.username,
            password: formData.password,
        });

        if (!requestValidation.success) {
            setApiError("Nieprawidłowe dane żądania");
            return;
        }

        const requestData = requestValidation.data;

        registerMutation.mutate(requestData, {
            onSuccess: (response) => {
                if (!response.success) {
                    setApiError(response.error || "Rejestracja nieudana");
                } else {
                    setSuccessMessage("Konto utworzone pomyślnie! Przekierowywanie do logowania...");
                    setTimeout(() => {
                        const params = searchParams.toString();
                        router.push("/auth/login" + (params ? `?${params}` : ""));
                    }, 2000);
                }
            },
            onError: (err) => {
                let errorMessage = "Wystąpił błąd";
                if (isApiError(err)) {
                    errorMessage = err.error_description || err.error;
                } else if (err instanceof Error) {
                    errorMessage = err.message;
                }
                setApiError(errorMessage);
            },
        });
    };

    const updateField = (field: keyof RegisterFormData, value: string) => {
        setFormData((prev) => ({ ...prev, [field]: value }));
        if (errors[field]) {
            setErrors((prev) => {
                const newErrors = { ...prev };
                delete newErrors[field];
                return newErrors;
            });
        }
    };

    const isLoading = registerMutation.isPending;

    if (isCheckingAuth) {
        return (
            <div className="flex items-center justify-center py-12">
                <div className="text-gray-500">Ładowanie...</div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            <div className="space-y-1">
                <h2 className="text-xl font-semibold text-gray-900">Utwórz konto</h2>
                <p className="text-sm text-gray-500">Zarejestruj się, aby rozpocząć</p>
            </div>

            {successMessage ? (
                <div className="flex flex-col items-center justify-center py-12 space-y-6 text-center">
                    <div className="w-16 h-16 rounded-full bg-green-50 flex items-center justify-center border border-green-200">
                        <CheckCircle className="w-8 h-8 text-green-500" />
                    </div>
                    <div className="space-y-2">
                        <p className="text-gray-900 font-medium">Konto utworzone pomyślnie!</p>
                        <p className="text-sm text-gray-500">Przekierowywanie do strony logowania...</p>
                    </div>
                </div>
            ) : (
                <form onSubmit={handleSubmit} className="space-y-5">
                    <div className="grid grid-cols-2 gap-4">
                        <Input
                            label="Imię"
                            type="text"
                            placeholder="Jan"
                            value={formData.first_name}
                            onChange={(e) => updateField("first_name", e.target.value)}
                            disabled={isLoading}
                            error={errors.first_name}
                        />

                        <Input
                            label="Nazwisko"
                            type="text"
                            placeholder="Kowalski"
                            value={formData.last_name}
                            onChange={(e) => updateField("last_name", e.target.value)}
                            disabled={isLoading}
                            error={errors.last_name}
                        />
                    </div>

                    <Input
                        label="Email"
                        type="email"
                        placeholder="nazwa@przyklad.pl"
                        value={formData.email}
                        onChange={(e) => updateField("email", e.target.value)}
                        disabled={isLoading}
                        error={errors.email}
                    />

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

                    <Input
                        label="Potwierdź hasło"
                        type="password"
                        placeholder="••••••••"
                        value={formData.confirmPassword}
                        onChange={(e) => updateField("confirmPassword", e.target.value)}
                        required
                        disabled={isLoading}
                        error={errors.confirmPassword}
                    />

                    {apiError && <p className="text-xs font-medium text-red-500">{apiError}</p>}

                    <div className="pt-1">
                        <Button fullWidth variant="primary" type="submit" disabled={isLoading}>
                            {isLoading ? "Tworzenie konta..." : "Zarejestruj się"}
                        </Button>
                    </div>
                </form>
            )}

            <div className="pt-2 border-t border-gray-200">
                <p className="text-center text-sm text-gray-500 mt-2">
                    Masz już konto?{" "}
                    <a
                        href={`/auth/login${searchParams.get("oidc_params") ? `?oidc_params=${encodeURIComponent(searchParams.get("oidc_params")!)}` : ""}`}
                        className="text-gray-900 hover:text-black font-medium underline underline-offset-4 transition-colors duration-200"
                    >
                        Zaloguj się
                    </a>
                </p>
            </div>
        </div>
    );
}

/**
 * Renders the registration page wrapped in a Suspense boundary that shows a fullscreen loading fallback while content loads.
 *
 * @returns The React element for the registration page.
 */
export default function RegisterPage() {
    return (
        <Suspense
            fallback={
                <div className="min-h-screen w-full flex items-center justify-center bg-gray-50">
                    <div className="text-gray-500">Ładowanie...</div>
                </div>
            }
        >
            <RegisterPageContent />
        </Suspense>
    );
}
