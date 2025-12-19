import Navbar from "@/authly/components/landing/Navbar";
import Hero from "@/authly/components/landing/Hero";
import Features from "@/authly/components/landing/Features";
import Footer from "@/authly/components/landing/Footer";
import CodeExamples from "@/authly/components/landing/CodeExamples";

export default function Home() {
    return (
        <main className="flex min-h-screen flex-col bg-black text-white font-display">
            <Navbar />
            <Hero />
            <section id="features">
                <Features />
            </section>
            <section id="examples">
                <CodeExamples />
            </section>
            <Footer />
        </main>
    );
}
