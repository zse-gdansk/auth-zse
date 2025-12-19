"use client";

import { useState } from "react";
import { Copy, Check, Terminal } from "lucide-react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
import Button from "@/authly/components/ui/Button";

const codeExamples = [
    {
        language: "python",
        label: "Python",
        available: true,
        code: `from authly_sdk import AuthlyClient, TokenInvalidError, TokenExpiredError

# 1. Initialize the client
client = AuthlyClient(
    issuer="https://auth.example.com",
    audience="your-api-identifier"
)

# 2. Verify a token:
try:
    token = "eyJhbGciOiJSUzI1NiIs..."
    claims = client.verify(token)
    
    # Access standard and custom claims with full IDE support
    print(f"User Subject: {claims['sub']}")
    print(f"Session ID: {claims['sid']}")
    print(f"Permissions: {claims['permissions']}")
    
except TokenExpiredError:
    print("The token has expired")
except TokenInvalidError as e:
    print(f"Invalid token: {e}")`,
    },
    {
        language: "go",
        label: "Go",
        available: false,
        code: `// Coming soon...`,
    },
    {
        language: "typescript",
        label: "TypeScript",
        available: false,
        code: `// Coming soon...`,
    },
];

// Custom dark theme for syntax highlighting
const customDarkTheme = {
    ...vscDarkPlus,
    'code[class*="language-"]': {
        ...vscDarkPlus['code[class*="language-"]'],
        background: "#0a0a0a",
        color: "#e5e5e5",
    },
    'pre[class*="language-"]': {
        ...vscDarkPlus['pre[class*="language-"]'],
        background: "#0a0a0a",
        padding: 0,
        margin: 0,
    },
};

export default function CodeExamples() {
    const [activeTab, setActiveTab] = useState(0);
    const [copied, setCopied] = useState(false);

    const handleCopy = () => {
        navigator.clipboard.writeText(codeExamples[activeTab].code);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <section className="relative py-24 md:py-32 bg-black">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                {/* Section Header */}
                <div className="max-w-3xl mb-16 md:mb-20">
                    <div className="inline-flex items-center gap-2 px-3 py-1 border border-white/10 text-white/60 text-xs tracking-widest uppercase mb-6">
                        <Terminal className="w-3 h-3" strokeWidth={2} strokeLinecap="square" />
                        DEVELOPER EXPERIENCE
                    </div>

                    <h2 className="text-4xl md:text-5xl lg:text-6xl font-light tracking-tight text-white mb-6">
                        START IN
                        <br />
                        <span className="text-white/60">5 MINUTES.</span>
                    </h2>

                    <p className="text-lg md:text-xl text-white/50 font-light leading-relaxed">
                        Drop-in authentication that actually works. No complex setup, no hidden gotchas. Just clean APIs
                        that do exactly what you expect.
                    </p>
                </div>

                {/* Code Block Container */}
                <div className="relative">
                    {/* Language Tabs */}
                    <div className="flex gap-2 mb-0 border-b border-white/5">
                        {codeExamples.map((example, index) => (
                            <button
                                key={index}
                                onClick={() => example.available && setActiveTab(index)}
                                disabled={!example.available}
                                className={`relative px-6 py-3 text-sm font-medium tracking-wide transition-all duration-200 ${
                                    activeTab === index && example.available
                                        ? "text-white"
                                        : example.available
                                          ? "text-white/40 hover:text-white/60"
                                          : "text-white/20 cursor-not-allowed"
                                }`}
                            >
                                {example.label}
                                {!example.available && (
                                    <span className="ml-2 text-[10px] text-white/30 uppercase">Soon</span>
                                )}
                                {activeTab === index && example.available && (
                                    <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-white" />
                                )}
                            </button>
                        ))}
                    </div>

                    {/* Code Block */}
                    <div className="relative group">
                        {/* Code Content */}
                        <div className="relative bg-[#0a0a0a] border border-white/10 p-6 overflow-x-auto">
                            {/* Copy Button */}
                            {codeExamples[activeTab].available && (
                                <button
                                    onClick={handleCopy}
                                    className="absolute top-4 right-4 p-2 hover:bg-white/5 transition-colors rounded hover:cursor-pointer"
                                    aria-label="Copy code"
                                >
                                    {copied ? (
                                        <Check
                                            className="w-4 h-4 text-green-400"
                                            strokeWidth={2}
                                            strokeLinecap="square"
                                        />
                                    ) : (
                                        <Copy
                                            className="w-4 h-4 text-white/40 hover:text-white/60"
                                            strokeWidth={2}
                                            strokeLinecap="square"
                                        />
                                    )}
                                </button>
                            )}

                            {codeExamples[activeTab].available ? (
                                <SyntaxHighlighter
                                    language={codeExamples[activeTab].language}
                                    style={customDarkTheme}
                                    customStyle={{
                                        background: "transparent",
                                        padding: 0,
                                        margin: 0,
                                        fontSize: "0.875rem",
                                        lineHeight: "1.75",
                                    }}
                                    codeTagProps={{
                                        style: {
                                            fontFamily: "var(--font-mono), monospace",
                                        },
                                    }}
                                >
                                    {codeExamples[activeTab].code}
                                </SyntaxHighlighter>
                            ) : (
                                <pre className="text-sm font-mono leading-relaxed h-[300px] flex items-center justify-center">
                                    <code className="text-white/30 italic">{codeExamples[activeTab].code}</code>
                                </pre>
                            )}
                        </div>

                        <div className="absolute -inset-0.5 bg-linear-to-r from-purple-500/10 to-blue-500/10 opacity-0 group-hover:opacity-100 blur-xl transition-opacity duration-500 -z-10" />
                    </div>
                </div>

                <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="p-6 border border-white/5 hover:border-white/10 transition-colors">
                        <div className="text-2xl font-light text-white mb-2">5 min</div>
                        <div className="text-white/40 text-sm">From zero to production</div>
                    </div>
                    <div className="p-6 border border-white/5 hover:border-white/10 transition-colors">
                        <div className="text-2xl font-light text-white mb-2">OIDC</div>
                        <div className="text-white/40 text-sm">Standard-compliant verification</div>
                    </div>
                    <div className="p-6 border border-white/5 hover:border-white/10 transition-colors">
                        <div className="text-2xl font-light text-white mb-2">0</div>
                        <div className="text-white/40 text-sm">Complex config files needed</div>
                    </div>
                </div>

                {/* Bottom CTA */}
                <div className="mt-12 flex flex-col sm:flex-row gap-4">
                    <Button variant="primary" size="lg" href="/docs">
                        READ THE DOCS
                    </Button>
                    <Button variant="outline" size="lg" href="https://github.com/anvoria/authly">
                        VIEW ON GITHUB
                    </Button>
                </div>
            </div>

            {/* Background Grid */}
            <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.02)_1px,transparent_1px)] bg-size-[64px_64px] mask-[radial-gradient(ellipse_50%_50%_at_50%_50%,black,transparent)] pointer-events-none" />
        </section>
    );
}
