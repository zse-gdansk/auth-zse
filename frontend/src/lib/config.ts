// OIDC Client Configuration for the Authly Dashboard itself
export const OIDC_CONFIG = {
    authority: process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000",
    client_id: "authly_authly_00000000",
    redirect_uri:
        typeof window !== "undefined" ? `${window.location.origin}/callback` : "http://localhost:3000/callback",
    response_type: "code",
    scope: "openid profile email",
};
