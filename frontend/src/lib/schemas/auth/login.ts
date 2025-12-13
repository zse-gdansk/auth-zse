import { z } from "zod";

/**
 * Schema for user login request
 */
export const loginRequestSchema = z
    .object({
        email: z.email().max(255).optional(),
        username: z.string().min(3).max(50).optional(),
        password: z.string().min(1).max(128),
    })
    .refine(
        (data) => {
            return data.email || data.username;
        },
        {
            message: "Either email or username must be provided",
        },
    );

/**
 * Type inferred from loginRequestSchema
 */
export type LoginRequest = z.infer<typeof loginRequestSchema>;

/**
 * Schema for user login response
 */
export const loginResponseSchema = z.object({
    success: z.boolean(),
    user_id: z.string().optional(),
    error: z.string().optional(),
    error_description: z.string().optional(),
});

/**
 * Type inferred from loginResponseSchema
 */
export type LoginResponse = z.infer<typeof loginResponseSchema>;
