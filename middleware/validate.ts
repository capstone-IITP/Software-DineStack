import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';

interface ValidationSchemas {
    body?: ZodSchema;
    params?: ZodSchema;
    query?: ZodSchema;
}

/**
 * Zod validation middleware factory.
 * Validates req.body, req.params, and/or req.query against provided schemas.
 * On failure, returns 400 with sanitized error details (no internal info leaked).
 */
export function validate(schemas: ValidationSchemas) {
    return (req: Request, res: Response, next: NextFunction): void => {
        const errors: { field: string; message: string }[] = [];

        if (schemas.body) {
            const result = schemas.body.safeParse(req.body);
            if (!result.success) {
                for (const issue of result.error.issues) {
                    errors.push({
                        field: issue.path.join('.') || 'body',
                        message: issue.message
                    });
                }
            } else {
                // Replace req.body with parsed (sanitized) data
                req.body = result.data;
            }
        }

        if (schemas.params) {
            const result = schemas.params.safeParse(req.params);
            if (!result.success) {
                for (const issue of result.error.issues) {
                    errors.push({
                        field: `params.${issue.path.join('.')}`,
                        message: issue.message
                    });
                }
            }
        }

        if (schemas.query) {
            const result = schemas.query.safeParse(req.query);
            if (!result.success) {
                for (const issue of result.error.issues) {
                    errors.push({
                        field: `query.${issue.path.join('.')}`,
                        message: issue.message
                    });
                }
            }
        }

        if (errors.length > 0) {
            res.status(400).json({
                error: 'Validation failed',
                details: errors
            });
            return;
        }

        next();
    };
}
