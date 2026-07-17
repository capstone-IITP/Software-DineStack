-- Releases display names from deleted/purged restaurant history.
-- Run against the cloud PostgreSQL database after deploying the matching Prisma schema.

DROP INDEX IF EXISTS "Restaurant_name_key";

CREATE INDEX IF NOT EXISTS "Restaurant_name_status_idx"
  ON "Restaurant" ("name", "status");
