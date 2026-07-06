-- Rename Device table columns to match backend code expectations
-- Safe migration: RENAME instead of DROP/CREATE

-- 1. Rename 'hash' to 'deviceId'
ALTER TABLE "Device" RENAME COLUMN "hash" TO "deviceId";

-- 2. Rename 'type' to 'role'
ALTER TABLE "Device" RENAME COLUMN "type" TO "role";

-- 3. Rename 'lastSeen' to 'lastUsed'
ALTER TABLE "Device" RENAME COLUMN "lastSeen" TO "lastUsed";

-- 4. Drop the 'status' column (no longer needed, role covers this)
ALTER TABLE "Device" DROP COLUMN IF EXISTS "status";
