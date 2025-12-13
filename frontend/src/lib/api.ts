import GeneralClient from "./globals/api/GeneralClient";
import {
    registerRequestSchema,
    registerResponseSchema,
    type RegisterRequest,
    type RegisterResponse,
} from "./schemas/auth/register";
import type { ApiError } from "./schemas/auth/login";

export type { ApiError };

export async function register(data: RegisterRequest): Promise<RegisterResponse> {
    const validatedData = registerRequestSchema.parse(data);

    const response = await GeneralClient.post<{ user: { id: string } }>("/auth/register", validatedData);

    if (!response.success) {
        if ("isRedirect" in response && response.isRedirect) {
            const errorResponse: RegisterResponse = {
                success: false,
                error: "redirect_occurred",
            };
            return registerResponseSchema.parse(errorResponse);
        }
        if ("error" in response) {
            const errorResponse: RegisterResponse = {
                success: false,
                error: response.error,
            };
            return registerResponseSchema.parse(errorResponse);
        }
        const errorResponse: RegisterResponse = {
            success: false,
            error: "unknown_error",
        };
        return registerResponseSchema.parse(errorResponse);
    }

    const successResponse: RegisterResponse = {
        success: true,
        data: response.data,
        message: response.message ?? "",
    };

    return registerResponseSchema.parse(successResponse);
}
