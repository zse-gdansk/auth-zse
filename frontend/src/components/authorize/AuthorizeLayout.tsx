"use client";

import React, { useEffect } from "react";
import Image from "next/image";

export interface AuthorizeLayoutProps {
    children: React.ReactNode;
}

/**
 * Layout wrapper for authorization screens that renders a centered, themed card with a header and body area.
 *
 * @param children - Content to render inside the layout's body area.
 * @returns The layout element containing the header (logo and title) and the provided children
 */
export default function AuthorizeLayout({ children }: AuthorizeLayoutProps) {
    useEffect(() => {
        document.body.classList.add("overflow-hidden");
        return () => {
            document.body.classList.remove("overflow-hidden");
        };
    }, []);

    return (
        <div className="min-h-screen w-full flex items-center justify-center bg-gray-50 p-4">
            <div className="w-full max-w-md relative">
                <div className="relative bg-white backdrop-blur-xl border border-gray-200 shadow-xl shadow-gray-200/50 overflow-hidden">
                    <div className="absolute inset-0 bg-linear-to-br from-black/2 to-transparent pointer-events-none" />

                    <div className="relative z-10">
                        <div className="flex px-8 pt-8 pb-6 border-b border-gray-200">
                            <div className="relative w-12 h-12">
                                <Image src="/images/logo.png" alt="Auth ZSE Logo" fill className="object-contain" />
                            </div>
                        </div>

                        <div className="px-8 py-8">{children}</div>
                    </div>
                </div>
            </div>
        </div>
    );
}
