import { z } from "zod";

/**
 * Schema for API error response
 */
export const apiErrorSchema = z.union([
    z.string(),
    z.object({
        code: z.string(),
        message: z.string(),
        details: z.unknown().optional(),
    }),
]);

/**
 * Type inferred from apiErrorSchema
 */
export type ApiError = z.infer<typeof apiErrorSchema>;

/**
 * Schema for user login request
 */
export const loginRequestSchema = z
    .object({
        email: z.string().email().max(255).optional().or(z.literal("")),
        username: z.string().min(3).max(50).optional().or(z.literal("")),
        password: z.string().min(1).max(128),
    })
    .refine(
        (data) => {
            return (data.email && data.email.length > 0) || (data.username && data.username.length > 0);
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
export const loginSuccessResponseSchema = z.object({
    success: z.literal(true),
    data: z.object({
        user: z
            .object({
                id: z.string(),
                username: z.string(),
                first_name: z.string(),
                last_name: z.string(),
                email: z.string().nullable(),
                is_active: z.boolean(),
                created_at: z.string(),
                updated_at: z.string(),
            })
            .loose(),
    }),
    message: z.string(),
});

/**
 * Schema for user login response error
 */
export const loginErrorResponseSchema = z.object({
    success: z.literal(false),
    error: apiErrorSchema,
});

/**
 * Schema for user login response
 */
export const loginResponseSchema = z.union([loginSuccessResponseSchema, loginErrorResponseSchema]);

/**
 * Type inferred from loginResponseSchema
 */
export type LoginResponse = z.infer<typeof loginResponseSchema>;
