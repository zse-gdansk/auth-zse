import type { Metadata, Viewport } from "next";
import { Sora, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import QueryProvider from "@/authly/components/providers/QueryProvider";
import AuthProvider from "@/authly/components/providers/AuthProvider";

const sora = Sora({
    subsets: ["latin"],
    variable: "--font-sora",
    display: "swap",
});

const mono = JetBrains_Mono({
    subsets: ["latin"],
    variable: "--font-mono",
    display: "swap",
});

export const metadata: Metadata = {
    title: {
        default: "Zespół Szkół Energetycznych",
        template: "%s · Zespół Szkół Energetycznych",
    },
    description:
        "Zespół Szkół Energetycznych - System autoryzacyjny",
    applicationName: "Zespół Szkół Energetycznych",
    generator: "Next.js",
    keywords: ["zse", "zespół szkoły energetycznych"],
    authors: [{ name: "Zespół Szkół Energetycznych" }],
    creator: "Zespół Szkół Energetycznych",
    publisher: "Zespół Szkół Energetycznych",
};

export const viewport: Viewport = {
    width: "device-width",
    initialScale: 1,
    themeColor: "#000000",
};

/**
 * Provide the application's root HTML structure, apply global font variables, and wrap page content with the QueryProvider.
 *
 * @param children - The application content to render inside the layout.
 * @returns The `<html>` element (lang="en") containing a `<body>` whose children are wrapped by the QueryProvider.
 */
export default function RootLayout({ children }: { children: React.ReactNode }) {
    return (
        <html lang="en" className={`${sora.variable} ${mono.variable}`}>
            <body className="font-display antialiased">
                <QueryProvider>
                    <AuthProvider>{children}</AuthProvider>
                </QueryProvider>
            </body>
        </html>
    );
}
