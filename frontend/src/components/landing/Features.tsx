"use client";

import { Shield, Zap, Code2, Lock, Globe, Wrench, Book } from "lucide-react";
import Button from "@/authly/components/ui/Button";

const features = [
    {
        icon: Shield,
        title: "Battle-Hardened Security",
        description:
            "Fully compliant with RFC 6749 and RFC 7636. Enforces PKCE for public clients and strict session validation to prevent replay attacks.",
    },
    {
        icon: Zap,
        title: "High-Performance Core",
        description:
            "Written in Go for raw speed. Optimized database queries and in-memory caching ensure sub-millisecond token validation.",
    },
    {
        icon: Lock,
        title: "Granular Permissions",
        description:
            "Bitmask-based permission system allows for extremely efficient and fine-grained access control down to specific resources.",
    },
    {
        icon: Code2,
        title: "Developer First",
        description:
            "Comprehensive TypeScript SDKs and a clean REST API make integration trivial. detailed error messages and predictable behavior.",
    },
    {
        icon: Globe,
        title: "Standardized OIDC",
        description:
            "Seamlessly integrates with any OIDC-compliant identity provider. Supports authorization code, refresh token, and client credentials flows.",
    },
    {
        icon: Wrench,
        title: "Self-Hosted Control",
        description:
            "Keep full ownership of your user data. deploy anywhere—from a single VPS to a Kubernetes cluster—with zero external dependencies.",
    },
];

export default function Features() {
    return (
        <section className="relative py-24 md:py-32 bg-black">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                {/* Section Header */}
                <div className="max-w-3xl mb-16 md:mb-20">
                    <h2 className="text-4xl md:text-5xl lg:text-6xl font-light tracking-tight text-white mb-6">
                        ENGINEERED FOR
                        <br />
                        <span className="text-white/60">SCALE & SECURITY.</span>
                    </h2>
                    <p className="text-lg md:text-xl text-white/50 font-light leading-relaxed">
                        Eliminate the complexity of building secure authentication. Deploy a production-ready identity
                        layer that scales with your infrastructure.
                    </p>
                </div>

                {/* Features Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 md:gap-8">
                    {features.map((feature, index) => {
                        const Icon = feature.icon;
                        return (
                            <div
                                key={index}
                                className="group relative p-8 border border-white/5 hover:border-white/20 bg-black hover:bg-white/2 transition-all duration-300"
                            >
                                {/* Icon */}
                                <div className="mb-6">
                                    <Icon
                                        className="w-8 h-8 text-white/80 group-hover:text-white transition-colors"
                                        strokeWidth={2}
                                        strokeLinecap="square"
                                    />
                                </div>

                                {/* Content */}
                                <h3 className="text-xl font-medium tracking-wide text-white mb-3">{feature.title}</h3>
                                <p className="text-white/50 font-light leading-relaxed text-sm">
                                    {feature.description}
                                </p>

                                {/* Hover Effect Line */}
                                <div className="absolute bottom-0 left-0 h-px w-0 bg-white/40 group-hover:w-full transition-all duration-500" />
                            </div>
                        );
                    })}
                </div>

                {/* Bottom CTA */}
                <div className="mt-16 md:mt-20 text-center">
                    <p className="text-white/40 text-sm tracking-wide uppercase mb-4">Ready to build?</p>
                    <Button
                        variant="primary"
                        size="lg"
                        href="/docs"
                        icon={<Book className="w-4 h-4" strokeWidth={2} strokeLinecap="square" />}
                    >
                        READ THE DOCUMENTATION
                    </Button>
                </div>
            </div>

            {/* Background Grid Pattern */}
            <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-size-[64px_64px] mask-[radial-gradient(ellipse_50%_50%_at_50%_50%,black,transparent)] pointer-events-none" />
        </section>
    );
}
