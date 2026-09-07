import { z } from 'zod';

/**
 * FR5: validate REST/mobile JSON payloads against a defined schema before
 * forwarding. Every schema is `.strict()` - rejects any property not
 * explicitly listed - which is the actual mechanism that stops mass
 * assignment / price tampering (doc's API3:2023 entry): the checkout schema
 * simply has no `price` field, so `{"item_id":12,"price":0.01}` fails
 * validation instead of silently passing an extra property through to a
 * backend that might trust it. String-typed fields (not z.any()/z.unknown())
 * also block NoSQL-injection-via-object-payload shapes like
 * `{"password": {"$ne": null}}`, since an object fails z.string().
 */

export const loginSchema = z
  .object({
    email: z.string().email().max(200).optional(),
    username: z.string().min(1).max(100).optional(),
    password: z.string().min(1).max(200),
  })
  .strict()
  .refine((data) => data.email || data.username, { message: 'email or username is required' });

export const checkoutSchema = z
  .object({
    items: z
      .array(
        z
          .object({
            item_id: z.union([z.string(), z.number()]),
            quantity: z.number().int().positive().max(1000),
          })
          .strict(),
      )
      .min(1)
      .max(100),
    payment_method: z.enum(['card', 'cash', 'wallet']).optional(),
    customer_id: z.union([z.string(), z.number()]).optional(),
  })
  .strict();

export const discountApplySchema = z
  .object({
    code: z
      .string()
      .min(1)
      .max(50)
      .regex(/^[A-Za-z0-9_-]+$/, 'code must be alphanumeric'),
    order_id: z.union([z.string(), z.number()]).optional(),
  })
  .strict();

export const inventoryUpdateSchema = z
  .object({
    quantity: z.number().int().min(0).max(1_000_000),
    reason: z.enum(['restock', 'sale', 'correction', 'damaged']).optional(),
  })
  .strict();
