"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

/**
 * Redirects the user to /dashboard/profile on mount and displays a full-screen "REDIRECTING..." message.
 *
 * The component triggers a client-side navigation to `/dashboard/profile` (replacing the current history entry)
 * when it mounts, and renders a centered, monospace, white message while the redirect occurs.
 *
 * @returns A React element that fills the viewport and displays the centered text "REDIRECTING...".
 */
export default function DashboardIndex() {
    const router = useRouter();

    useEffect(() => {
        router.replace("/dashboard/profile");
    }, [router]);

    return (
        <div className="min-h-screen bg-black flex items-center justify-center text-white font-mono text-sm tracking-widest">
            REDIRECTING...
        </div>
    );
}