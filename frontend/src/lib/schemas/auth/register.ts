import { z } from "zod";

/**
 * Schema for user registration request
 */
export const registerRequestSchema = z.object({
    first_name: z.string().min(1).max(100).optional(),
    last_name: z.string().min(1).max(100).optional(),
    email: z.email().max(255).optional(),
    username: z.string().min(3).max(50),
    password: z.string().min(8).max(128),
});

/**
 * Type inferred from registerRequestSchema
 */
export type RegisterRequest = z.infer<typeof registerRequestSchema>;

/**
 * Schema for user registration response
 */
export const registerResponseSchema = z.object({
    success: z.boolean(),
    user_id: z.string().optional(),
    error: z.string().optional(),
    error_description: z.string().optional(),
});

/**
 * Type inferred from registerResponseSchema
 */
export type RegisterResponse = z.infer<typeof registerResponseSchema>;

/**
 * Schema for client-side registration form (includes password confirmation)
 */
export const registerFormSchema = z
    .object({
        first_name: z.string().min(1).max(100).optional().or(z.literal("")),
        last_name: z.string().min(1).max(100).optional().or(z.literal("")),
        email: z.email().max(255).optional().or(z.literal("")),
        username: z.string().min(3).max(50),
        password: z.string().min(8).max(128),
        confirmPassword: z.string(),
    })
    .refine((data) => data.password === data.confirmPassword, {
        message: "Passwords do not match",
        path: ["confirmPassword"],
    });

/**
 * Type inferred from registerFormSchema
 */
export type RegisterFormData = z.infer<typeof registerFormSchema>;
