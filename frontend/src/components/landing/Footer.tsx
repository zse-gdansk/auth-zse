"use client";

import Link from "next/link";
import Image from "next/image";

const footerLinks = [
    { label: "DOCS", href: "/docs" },
    {
        label: "GITHUB",
        href: "https://github.com/anvoria/authly",
        external: true,
    },
];

export default function Footer() {
    return (
        <footer className="relative bg-black border-t border-white/5">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16 md:py-24">
                <div className="max-w-3xl">
                    {/* Brand */}
                    <div className="flex items-center gap-3 mb-8">
                        <div className="relative w-7 h-7 md:w-8 md:h-8 shrink-0">
                            <Image
                                src="/images/logo.svg"
                                alt="Authly Logo"
                                fill
                                className="object-contain filter brightness-0 invert"
                            />
                        </div>
                        <span className="text-lg md:text-xl font-medium tracking-[0.2em] text-white">AUTHLY</span>
                    </div>

                    {/* Links */}
                    <div className="flex flex-wrap items-center gap-6 md:gap-8 mb-12">
                        {footerLinks.map((link) => (
                            <Link
                                key={link.label}
                                href={link.href}
                                target={link.external ? "_blank" : undefined}
                                rel={link.external ? "noopener noreferrer" : undefined}
                                className="text-sm tracking-wide text-white/50 hover:text-white transition-colors uppercase font-light"
                            >
                                {link.label}
                            </Link>
                        ))}
                    </div>

                    {/* Copyright */}
                    <p className="text-sm text-white/40 font-light">
                        © {new Date().getFullYear()} Authly. All rights reserved.
                    </p>
                </div>
            </div>
        </footer>
    );
}
