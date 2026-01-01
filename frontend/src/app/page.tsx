"use client";

import Image from "next/image";
import Button from "@/authly/components/ui/Button";

export default function Home() {
    return (
        <main className="flex min-h-screen flex-col bg-white text-gray-900 font-display selection:bg-gray-100">
            <header className="fixed top-0 left-0 right-0 z-50 bg-white/80 backdrop-blur-md border-b border-gray-100">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 md:h-20 flex items-center justify-between">
                    <div className="relative w-12 h-12">
                        <Image src="/images/logo.png" alt="Auth ZSE Logo" fill className="object-contain" />
                    </div>
                    <div className="flex items-center gap-3">
                        <Button href="/auth/login" variant="ghost" size="sm">
                            Logowanie
                        </Button>
                        <Button href="/auth/register" variant="primary" size="sm">
                            Rejestracja
                        </Button>
                    </div>
                </div>
            </header>

            <section className="flex-1 flex items-center justify-center pt-20 pb-16">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 w-full">
                    <div className="max-w-3xl mx-auto text-center space-y-8">
                        <h1 className="text-5xl sm:text-6xl md:text-7xl font-bold tracking-tight text-gray-900">
                            Bezpieczeństwo
                            <span className="block text-gray-400 font-light mt-2">w Twoich rękach.</span>
                        </h1>

                        <p className="text-lg sm:text-xl text-gray-500 max-w-2xl mx-auto leading-relaxed font-light">
                            Nowoczesna platforma autoryzacyjna dla ZSE. Prosta integracja, pełna kontrola i
                            niezawodność.
                        </p>

                        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
                            <Button
                                href="/auth/register"
                                variant="primary"
                                size="lg"
                                className="w-full sm:w-auto min-w-[200px]"
                            >
                                Rozpocznij
                            </Button>
                            <Button
                                href="https://github.com/zse-gdansk/auth-zse"
                                variant="outline"
                                size="lg"
                                className="w-full sm:w-auto min-w-[200px]"
                            >
                                Dokumentacja
                            </Button>
                        </div>
                    </div>
                </div>
            </section>

            <footer className="border-t border-gray-100 bg-white">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex flex-col md:flex-row items-center justify-between gap-4">
                    <div className="flex items-center gap-2">
                        <div className="relative w-12 h-12">
                            <Image src="/images/logo.png" alt="ZSE Logo" fill className="object-contain" />
                        </div>
                    </div>
                    <p className="text-sm text-gray-400">
                        &copy; {new Date().getFullYear()} ZSE. Wszelkie prawa zastrzeżone.
                    </p>
                </div>
            </footer>
        </main>
    );
}
