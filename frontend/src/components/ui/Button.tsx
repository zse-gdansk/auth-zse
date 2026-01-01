import React from "react";
import Link from "next/link";
import { cn } from "@/authly/lib/utils";

export type ButtonVariant = "primary" | "secondary" | "outline" | "ghost";
export type ButtonSize = "sm" | "md" | "lg";

interface ButtonPropsBase {
    variant?: ButtonVariant;
    size?: ButtonSize;
    icon?: React.ReactNode;
    iconPosition?: "left" | "right";
    fullWidth?: boolean;
    children: React.ReactNode;
    className?: string;
}

interface ButtonAsButton extends ButtonPropsBase, Omit<React.ButtonHTMLAttributes<HTMLButtonElement>, "children"> {
    href?: never;
}

interface ButtonAsAnchor
    extends ButtonPropsBase, Omit<React.AnchorHTMLAttributes<HTMLAnchorElement>, "children" | "href"> {
    href: string;
}

export type ButtonProps = ButtonAsButton | ButtonAsAnchor;

const variantStyles: Record<ButtonVariant, string> = {
    primary:
        "bg-gray-900 text-white hover:bg-gray-800 hover:shadow-lg border border-transparent",
    secondary: "bg-gray-100 text-gray-900 hover:bg-gray-200 border border-transparent",
    outline:
        "border border-gray-200 text-gray-900 hover:bg-gray-50 hover:border-gray-300 hover:shadow-sm",
    ghost: "text-gray-600 hover:text-gray-900 hover:bg-gray-100 border border-transparent",
};

const sizeStyles: Record<ButtonSize, string> = {
    sm: "px-4 py-2 text-xs",
    md: "px-6 py-2.5 text-sm",
    lg: "px-8 py-4 text-sm",
};

/**
 * Renders a styled interactive element that is either a native button or a Next.js Link anchor, with configurable visual variant, size, icon placement, and width.
 *
 * @param variant - Visual style to apply: "primary" | "secondary" | "outline" | "ghost".
 * @param size - Size preset to apply: "sm" | "md" | "lg".
 * @param href - If provided, the component renders an anchor via Next.js Link pointing to this URL; otherwise it renders a native `<button>`.
 * @param icon - Optional element displayed alongside the label.
 * @param iconPosition - Position of the `icon` relative to the label: "left" or "right".
 * @param fullWidth - When true, the element stretches to fill its container's width.
 * @param className - Additional CSS class names appended to the computed styles.
 * @param children - Visible label/content of the button.
 * @returns The rendered anchor element when `href` is provided, otherwise a `<button>` element.
 */
export default function Button({
    variant = "primary",
    size = "md",
    icon,
    iconPosition = "right",
    fullWidth = false,
    className,
    children,
    ...props
}: ButtonProps) {
    const baseStyles = cn(
        "inline-flex items-center justify-center gap-2",
        "font-medium tracking-widest uppercase",
        "cursor-pointer",
        "transition-all duration-300 ease-out",
        "focus:outline-none focus:ring-2 focus:ring-gray-900/20 focus:ring-offset-2 focus:ring-offset-white",
        "disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-current",
        "relative overflow-hidden group",
        variantStyles[variant],
        sizeStyles[size],
        fullWidth && "w-full",
        className,
    );

    const content = (
        <>
            {icon && iconPosition === "left" && <span className="inline-flex items-center">{icon}</span>}
            <span className="relative z-10">{children}</span>
            {icon && iconPosition === "right" && <span className="inline-flex items-center">{icon}</span>}
            <span className="absolute inset-0 -translate-x-full group-hover:translate-x-full transition-transform duration-700 bg-linear-to-r from-transparent via-white/10 to-transparent" />
        </>
    );

    if ("href" in props && typeof props.href === "string") {
        const { href, ...anchorProps } = props as ButtonAsAnchor;
        return (
            <Link href={href} className={baseStyles} {...anchorProps}>
                {content}
            </Link>
        );
    }

    return (
        <button className={baseStyles} {...(props as React.ButtonHTMLAttributes<HTMLButtonElement>)}>
            {content}
        </button>
    );
}