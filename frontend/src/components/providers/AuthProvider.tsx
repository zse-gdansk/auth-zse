"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { getMe } from "@/authly/lib/api";

interface User {
    id: string;
    username: string;
    first_name: string;
    last_name: string;
    email: string | null;
    is_active: boolean;
    created_at: string;
    updated_at: string;
}

interface AuthContextType {
    user: User | null;
    permissions: Record<string, number>;
    isAuthenticated: boolean;
    isLoading: boolean;
    refreshAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
    user: null,
    permissions: {},
    isAuthenticated: false,
    isLoading: true,
    refreshAuth: async () => {},
});

export const useAuth = () => useContext(AuthContext);

export default function AuthProvider({ children }: { children: React.ReactNode }) {
    const [user, setUser] = useState<User | null>(null);
    const [permissions, setPermissions] = useState<Record<string, number>>({});
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isLoading, setIsLoading] = useState(true);

    const refreshAuth = useCallback(async () => {
        setIsLoading(true);
        try {
            const response = await getMe();
            if (response.success && response.data) {
                setUser(response.data.user);
                setPermissions(response.data.permissions || {});
                setIsAuthenticated(true);
            } else {
                setUser(null);
                setPermissions({});
                setIsAuthenticated(false);
            }
        } catch (error) {
            console.error("Failed to fetch auth info:", error);
            setUser(null);
            setPermissions({});
            setIsAuthenticated(false);
        } finally {
            setIsLoading(false);
        }
    }, []);

    useEffect(() => {
        refreshAuth();
    }, [refreshAuth]);

    return (
        <AuthContext.Provider
            value={{
                user,
                permissions,
                isAuthenticated,
                isLoading,
                refreshAuth,
            }}
        >
            {children}
        </AuthContext.Provider>
    );
}
