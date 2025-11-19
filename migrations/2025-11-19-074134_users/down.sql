-- This file should undo anything in `up.sql`
-- Drop indexes (in reverse order of creation)
DROP INDEX IF EXISTS users_is_active_email_idx;
DROP INDEX IF EXISTS users_is_active_idx;

-- Drop the users table
DROP TABLE IF EXISTS users;
