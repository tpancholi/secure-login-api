-- Extensions (must be superuser)
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

---------------------------
-- Create Migration User --
---------------------------

CREATE USER migration_user WITH PASSWORD 'migrate123';

-- Full database privileges for migrations
GRANT CONNECT ON DATABASE datamover TO migration_user;
ALTER DATABASE datamover OWNER TO migration_user;

-- Give migration_user full DDL control
ALTER SCHEMA public OWNER TO migration_user;

-- Allow creating new objects
GRANT CREATE, USAGE ON SCHEMA public TO migration_user;

----------------------
-- Create App User  --
----------------------

CREATE USER app_user WITH PASSWORD 'app123';

GRANT CONNECT ON DATABASE datamover TO app_user;

-- App user can access tables but cannot alter schema
GRANT USAGE ON SCHEMA public TO app_user;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;

-- Ensure privileges apply to future tables created by migration_user
ALTER DEFAULT PRIVILEGES FOR USER migration_user IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;

ALTER DEFAULT PRIVILEGES FOR USER migration_user IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO app_user;
