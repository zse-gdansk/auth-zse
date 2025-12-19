"use client";

import Image from "next/image";
import { ArrowRight } from "lucide-react";
import Button from "@/authly/components/ui/Button";

export default function Hero() {
    return (
        <section className="relative min-h-screen flex items-center overflow-hidden bg-black">
            {/* Content */}
            <div className="relative z-10 w-full py-24 md:py-32">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="max-w-3xl">
                        {/* Headline */}
                        <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl xl:text-8xl font-light tracking-tight leading-[1.1] text-white mb-6">
                            AUTHENTICATION
                            <br />
                            <span className="text-white/80">DONE RIGHT.</span>
                        </h1>

                        {/* Subheadline */}
                        <p className="text-lg md:text-xl text-white/50 max-w-2xl mb-8 sm:mb-10 md:mb-12 font-light leading-relaxed">
                            The authentication infrastructure designed for modern applications. Simple API, granular
                            control, and uncompromising security. Self-host it or use our cloud—both work perfectly.
                            Built by developers, for developers.
                        </p>

                        {/* CTA */}
                        <div className="flex flex-col sm:flex-row gap-3 sm:gap-4">
                            <Button
                                variant="primary"
                                size="lg"
                                icon={<ArrowRight className="w-4 h-4" strokeWidth={2} strokeLinecap="square" />}
                                iconPosition="right"
                                className="w-full sm:w-auto"
                            >
                                GET STARTED
                            </Button>
                            <Button variant="outline" size="lg" className="w-full sm:w-auto" disabled>
                                VIEW DOCS
                            </Button>
                        </div>

                        {/* Trust Indicators */}
                        <div className="mt-12 sm:mt-14 md:mt-16 flex flex-wrap gap-6 sm:gap-8 md:gap-12 text-xs sm:text-sm">
                            <div>
                                <div className="text-white/60 tracking-wide uppercase mb-1">OIDC & OAuth2</div>
                                <div className="text-white/40 text-[10px] sm:text-xs">Full Compliance</div>
                            </div>
                            <div>
                                <div className="text-white/60 tracking-wide uppercase mb-1">High Performance</div>
                                <div className="text-white/40 text-[10px] sm:text-xs">Sub-50ms Latency</div>
                            </div>
                            <div>
                                <div className="text-white/60 tracking-wide uppercase mb-1">Granular Access</div>
                                <div className="text-white/40 text-[10px] sm:text-xs">Bitmask Permissions</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Hero Image */}
            <div className="absolute bottom-4 right-0 w-full md:w-3/5 lg:w-1/2 h-[60vh] md:h-[80vh] opacity-60 md:opacity-80 hidden md:block">
                <Image
                    src="/images/hero-image.webp"
                    alt="Guardian protecting authentication"
                    fill
                    className="object-cover object-bottom"
                    priority
                    quality={90}
                />
            </div>

            {/* Gradient Overlay */}
            <div className="absolute inset-0 bg-linear-to-r from-black via-black/95 to-transparent pointer-events-none" />
            <div className="absolute inset-0 bg-linear-to-t from-black via-transparent to-transparent pointer-events-none" />
        </section>
    );
}
