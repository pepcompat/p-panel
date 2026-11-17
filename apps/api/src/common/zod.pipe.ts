import { type PipeTransform } from '@nestjs/common';
import type { ZodTypeAny, z } from 'zod';
import { AppError } from './app-error';
import { zodDetails } from './exception.filter';

/** Validates a body with a shared-contracts Zod schema → 422 VALIDATION_FAILED on error. */
export class ZodPipe<S extends ZodTypeAny> implements PipeTransform<unknown, z.infer<S>> {
  constructor(private readonly schema: S) {}
  transform(value: unknown): z.infer<S> {
    const r = this.schema.safeParse(value ?? {});
    if (!r.success) throw AppError.validation(zodDetails(r.error));
    return r.data;
  }
}

export function parseWith<S extends ZodTypeAny>(schema: S, value: unknown): z.infer<S> {
  return new ZodPipe(schema).transform(value);
}
