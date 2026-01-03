import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Combines class name inputs and returns a merged Tailwind-compatible class string.
 *
 * @param inputs - Class names or values accepted by `clsx` (strings, arrays, objects, etc.)
 * @returns The resulting class string with Tailwind class conflicts resolved
 */
export function cn(...inputs: ClassValue[]) {
    return twMerge(clsx(inputs));
}

/**
 * Extracts a human-readable error message from an error object or string.
 *
 * @param error - The error object or string
 * @returns A string representation of the error
 */
export function extractErrorMessage(error: unknown): string {
    if (typeof error === "string") {
        return error;
    }

    if (typeof error === "object" && error !== null) {
        if ("message" in error && typeof (error as { message: unknown }).message === "string") {
            return (error as { message: string }).message;
        }
        if ("error" in error && typeof (error as { error: unknown }).error === "string") {
            return (error as { error: string }).error;
        }
        if (
            "error_description" in error &&
            typeof (error as { error_description: unknown }).error_description === "string"
        ) {
            return (error as { error_description: string }).error_description;
        }
    }

    return "An unknown error occurred";
}
