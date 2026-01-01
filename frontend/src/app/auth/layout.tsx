import AuthorizeLayout from "@/authly/components/authorize/AuthorizeLayout";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
    return <AuthorizeLayout>{children}</AuthorizeLayout>;
}
