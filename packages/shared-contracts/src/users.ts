import { z } from 'zod';
import { ROLE_KEYS } from './permissions';
import { passwordSchema } from './auth';

export const SCOPE_TYPES = ['global', 'environment', 'project', 'server'] as const;

export const createRoleBindingSchema = z
  .object({
    roleKey: z.enum(ROLE_KEYS),
    scopeType: z.enum(SCOPE_TYPES),
    scopeId: z.string().trim().min(1).max(128).optional(),
  })
  .strict()
  .refine((b) => (b.scopeType === 'global') === (b.scopeId === undefined), {
    message: 'scopeId is required for non-global scopes and forbidden for global',
    path: ['scopeId'],
  });
export type CreateRoleBindingInput = z.infer<typeof createRoleBindingSchema>;

export const createUserSchema = z
  .object({
    email: z.string().trim().toLowerCase().email().max(254),
    password: passwordSchema,
    displayName: z.string().trim().min(1).max(100),
    bindings: z.array(createRoleBindingSchema).max(20).optional(),
  })
  .strict();
export type CreateUserInput = z.infer<typeof createUserSchema>;
