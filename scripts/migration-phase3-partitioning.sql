-- ============================================================================
-- LogVault — Phase 3 Migration: convert existing syslog_entries to PARTITIONED
-- ============================================================================
--
-- *** MANUAL-RUN ONLY — NOT part of the idempotent schema.sql run. ***
--
-- This converts the EXISTING, populated, non-partitioned `syslog_entries`
-- table on the live server into the daily-RANGE-partitioned design that fresh
-- installs get from scripts/schema.sql.
--
-- PRE-FLIGHT (do these BEFORE running):
--   1. RUN IN A MAINTENANCE WINDOW. This takes a brief ACCESS EXCLUSIVE lock
--      while renaming/attaching the table — the collector should be stopped or
--      will briefly block on INSERT:
--         nssm stop LogVault-Collector
--         nssm stop LogVault-API
--   2. TAKE A BACKUP FIRST (single source of truth for rollback):
--         pg_dump -U postgres -d logvault -t syslog_entries -Fc \
--             -f syslog_entries_prephase3.dump
--      (or a full DB dump). Verify the dump completes with no error.
--   3. RUN AS THE postgres SUPERUSER (owns the table + sequence; needs to
--      create SECURITY DEFINER functions):
--         psql -U postgres -d logvault -f migration-phase3-partitioning.sql
--
-- APPROACH — ATTACH the legacy table (no row copy):
--   We rename the existing table to syslog_entries_legacy and ATTACH it as a
--   single partition covering [min(received_at) .. cutover) of the new
--   partitioned parent. This avoids copying potentially millions of rows.
--   New rows flow into fresh daily partitions created from the cutover date on.
--
--   Trade-off vs. copy/INSERT-SELECT into daily partitions:
--     ATTACH  -> instant, no row movement, but the historical data stays in one
--                big legacy partition (it ages out in one DROP once the whole
--                legacy range passes the retention horizon). PRIMARY approach.
--     COPY    -> would split history into per-day partitions (cleaner aging)
--                but rewrites every row (slow, doubles disk during migration).
--                Not used here.
--
--   ATTACH requirements handled below:
--     * legacy table must have a CHECK constraint matching the partition bound
--       (received_at >= min AND received_at < cutover) so Postgres can attach
--       without a full scan-validate beyond the constraint check.
--     * legacy table column layout must match the new parent exactly (it does,
--       since it WAS syslog_entries — we only ADD the new hash columns).
--
-- INTEGRITY HASHES: legacy rows keep prev_hash / entry_hash = NULL. The tamper-
-- evidence hash chain starts fresh from the first row inserted AFTER migration.
-- This is expected and fine.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 0. Compute the legacy partition bounds DYNAMICALLY from the actual data, so
--    this works no matter when it is run:
--      lower bound = date_trunc('day', MIN(received_at))   (start of earliest day)
--      upper bound = date_trunc('day', now()) + 1 day      (start of TOMORROW)
--    Using TOMORROW as the upper bound is critical: today's rows run right up to
--    now(), so a "today 00:00" cutover would leave them OUTSIDE the legacy range
--    and the ATTACH CHECK would fail. Tomorrow's midnight guarantees every
--    existing row (including today's) fits inside the legacy partition.
-- ---------------------------------------------------------------------------
-- We use a temp table to stash the computed bounds so later steps can read them.
CREATE TEMP TABLE _phase3_bounds ON COMMIT DROP AS
SELECT
    MIN(received_at)                             AS min_raw,
    date_trunc('day', now()) + INTERVAL '1 day'  AS cutover
FROM syslog_entries;

-- ---------------------------------------------------------------------------
-- 1. Add the new integrity columns to the EXISTING table BEFORE renaming, so
--    the legacy table's column layout matches the new parent for ATTACH.
-- ---------------------------------------------------------------------------
ALTER TABLE syslog_entries ADD COLUMN IF NOT EXISTS prev_hash  BYTEA;
ALTER TABLE syslog_entries ADD COLUMN IF NOT EXISTS entry_hash BYTEA;
-- (category / risk_score already exist on live installs.)

-- ---------------------------------------------------------------------------
-- 2. Rename existing table -> syslog_entries_legacy.
--    Its indexes/constraints/sequence ownership ride along with the rename.
-- ---------------------------------------------------------------------------
ALTER TABLE syslog_entries RENAME TO syslog_entries_legacy;

-- The old PRIMARY KEY was on id alone. A partition CANNOT have a PK that
-- differs from / is incompatible with the parent's composite PK, and an
-- attached partition does not need to keep the old single-column PK. Drop it
-- so ATTACH is clean. (Sequence is independent of this constraint.)
ALTER TABLE syslog_entries_legacy DROP CONSTRAINT IF EXISTS syslog_entries_pkey;

-- Rename legacy indexes out of the way so the new parent can create identically
-- named indexes that propagate to all partitions. (Index names are unique per
-- schema.) We keep the legacy indexes (renamed) so the legacy partition stays
-- fast; ATTACH will match them to the parent's indexes by definition.
ALTER INDEX IF EXISTS idx_syslog_source_ip          RENAME TO idx_syslog_source_ip_legacy;
ALTER INDEX IF EXISTS idx_syslog_severity           RENAME TO idx_syslog_severity_legacy;
ALTER INDEX IF EXISTS idx_syslog_vendor             RENAME TO idx_syslog_vendor_legacy;
ALTER INDEX IF EXISTS idx_syslog_source_host        RENAME TO idx_syslog_source_host_legacy;
ALTER INDEX IF EXISTS idx_syslog_structured         RENAME TO idx_syslog_structured_legacy;
ALTER INDEX IF EXISTS idx_syslog_message            RENAME TO idx_syslog_message_legacy;
ALTER INDEX IF EXISTS idx_syslog_received           RENAME TO idx_syslog_received_legacy;
ALTER INDEX IF EXISTS idx_syslog_category           RENAME TO idx_syslog_category_legacy;
ALTER INDEX IF EXISTS idx_syslog_risk_score         RENAME TO idx_syslog_risk_score_legacy;
ALTER INDEX IF EXISTS idx_syslog_received_vendor    RENAME TO idx_syslog_received_vendor_legacy;
ALTER INDEX IF EXISTS idx_syslog_received_severity  RENAME TO idx_syslog_received_severity_legacy;
ALTER INDEX IF EXISTS idx_syslog_received_category  RENAME TO idx_syslog_received_category_legacy;
ALTER INDEX IF EXISTS idx_syslog_received_source    RENAME TO idx_syslog_received_source_legacy;
ALTER INDEX IF EXISTS idx_syslog_message_trgm       RENAME TO idx_syslog_message_trgm_legacy;
ALTER INDEX IF EXISTS idx_syslog_subcategory        RENAME TO idx_syslog_subcategory_legacy;

-- ---------------------------------------------------------------------------
-- 3. Create the new PARTITIONED parent with the SAME columns + composite PK.
--    The BIGSERIAL sequence already exists (created by the original
--    BIGSERIAL/PRIMARY KEY). We rebuild id as a plain bigint and re-point its
--    DEFAULT at the SAME sequence so id keeps incrementing across the cutover.
-- ---------------------------------------------------------------------------
-- The original sequence is conventionally named syslog_entries_id_seq. It was
-- renamed along with the table? No — sequences are NOT auto-renamed by ALTER
-- TABLE ... RENAME. So it is still `syslog_entries_id_seq`. Confirm with:
--   \ds syslog_entries*           (before running, if unsure)

CREATE TABLE syslog_entries (
    id              BIGINT          NOT NULL DEFAULT nextval('syslog_entries_id_seq'),
    received_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    log_timestamp   TIMESTAMPTZ,
    source_ip       INET            NOT NULL,
    source_host     TEXT,
    facility        SMALLINT,
    severity        SMALLINT        NOT NULL DEFAULT 6,
    severity_label  TEXT,
    facility_label  TEXT,
    vendor          TEXT            DEFAULT 'generic',
    program         TEXT,
    pid             INTEGER,
    message         TEXT            NOT NULL,
    raw_message     TEXT,
    structured_data JSONB,
    is_parsed       BOOLEAN         DEFAULT FALSE,
    parser_version  TEXT,
    category        TEXT,
    risk_score      SMALLINT        DEFAULT 0,
    prev_hash       BYTEA,
    entry_hash      BYTEA,
    PRIMARY KEY (id, received_at)
) PARTITION BY RANGE (received_at);

-- Re-assert sequence ownership to the new table's id column so dropping the
-- legacy table later never drops the sequence.
ALTER SEQUENCE syslog_entries_id_seq OWNED BY syslog_entries.id;

-- ---------------------------------------------------------------------------
-- 4. Recreate ALL indexes on the new parent (plain — CONCURRENTLY is not
--    allowed on a partitioned parent). These match scripts/schema.sql exactly
--    and propagate to every partition (including the attached legacy one).
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_syslog_id             ON syslog_entries (id);
CREATE INDEX IF NOT EXISTS idx_syslog_source_ip      ON syslog_entries (source_ip, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_severity       ON syslog_entries (severity, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_vendor         ON syslog_entries (vendor, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_source_host    ON syslog_entries (source_host, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_structured     ON syslog_entries USING GIN (structured_data);
CREATE INDEX IF NOT EXISTS idx_syslog_message        ON syslog_entries USING GIN (to_tsvector('english', message));
CREATE INDEX IF NOT EXISTS idx_syslog_received       ON syslog_entries (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_category       ON syslog_entries (category, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_risk_score     ON syslog_entries (risk_score DESC, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_received_vendor   ON syslog_entries (received_at DESC, vendor);
CREATE INDEX IF NOT EXISTS idx_syslog_received_severity ON syslog_entries (received_at DESC, severity);
CREATE INDEX IF NOT EXISTS idx_syslog_received_category ON syslog_entries (received_at DESC, category);
CREATE INDEX IF NOT EXISTS idx_syslog_received_source   ON syslog_entries (received_at DESC, source_ip, source_host, vendor);
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_syslog_message_trgm   ON syslog_entries USING GIN (message gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_syslog_subcategory
  ON syslog_entries ((structured_data->>'subcategory'))
  WHERE structured_data->>'subcategory' IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 5. DEFAULT partition (catch-all safety net).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS syslog_entries_default
  PARTITION OF syslog_entries DEFAULT;

-- ---------------------------------------------------------------------------
-- 6. ATTACH the legacy table as a single historical partition covering
--    [min_received .. cutover).
--    A matching CHECK constraint lets Postgres validate the bound cheaply.
-- ---------------------------------------------------------------------------
DO $mig$
DECLARE
    v_min_raw timestamptz;
    v_min     timestamptz;
    v_cutover timestamptz;
BEGIN
    SELECT min_raw, cutover INTO v_min_raw, v_cutover FROM _phase3_bounds;

    -- Guard: if the table was empty, there is nothing to attach — just drop
    -- the empty legacy table and let daily partitions handle everything.
    IF v_min_raw IS NULL THEN
        EXECUTE 'DROP TABLE IF EXISTS syslog_entries_legacy';
        RAISE NOTICE 'No legacy rows; dropped empty legacy table.';
        RETURN;
    END IF;

    -- Lower bound = start of the earliest data day; upper bound = tomorrow 00:00
    -- (computed in step 0) so every existing row, including today's, fits.
    v_min := date_trunc('day', v_min_raw);

    -- Add a CHECK matching the intended partition bound so ATTACH is fast.
    EXECUTE format(
        'ALTER TABLE syslog_entries_legacy ADD CONSTRAINT syslog_entries_legacy_range
           CHECK (received_at >= %L AND received_at < %L)',
        v_min, v_cutover
    );

    EXECUTE format(
        'ALTER TABLE syslog_entries ATTACH PARTITION syslog_entries_legacy
           FOR VALUES FROM (%L) TO (%L)',
        v_min, v_cutover
    );

    RAISE NOTICE 'Attached legacy partition for range [% .. %).', v_min, v_cutover;
END;
$mig$;

-- ---------------------------------------------------------------------------
-- 7. Create daily partitions going forward (+7d), using the management function
--    (created next). Today is already covered by the legacy partition, so the
--    function skips today (overlap) and creates tomorrow .. +7d.
-- ---------------------------------------------------------------------------

-- Partition-management functions (identical to scripts/schema.sql — created
-- here so the migration is self-contained; CREATE OR REPLACE keeps them in
-- sync if schema.sql is re-run afterward).
CREATE OR REPLACE FUNCTION ensure_syslog_partitions(days_ahead integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $func$
DECLARE
    d            date;
    part_name    text;
    created_cnt  integer := 0;
BEGIN
    IF days_ahead IS NULL OR days_ahead < 0 THEN
        days_ahead := 0;
    END IF;
    FOR d IN
        SELECT (current_date + g) FROM generate_series(0, days_ahead) AS g
    LOOP
        part_name := 'syslog_entries_p' || to_char(d, 'YYYYMMDD');
        IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = part_name) THEN
            BEGIN
                EXECUTE format(
                    'CREATE TABLE %I PARTITION OF syslog_entries FOR VALUES FROM (%L) TO (%L)',
                    part_name, d::text, (d + 1)::text
                );
                created_cnt := created_cnt + 1;
            EXCEPTION WHEN others THEN
                -- A daily partition can overlap the legacy partition right after
                -- migration (the migration day is inside the legacy range). Skip
                -- it instead of aborting the whole call.
                RAISE NOTICE 'Skipped partition % (%)', part_name, SQLERRM;
            END;
        END IF;
    END LOOP;
    RETURN created_cnt;
END;
$func$;

CREATE OR REPLACE FUNCTION drop_old_syslog_partitions(retention_days integer)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $func$
DECLARE
    rec          record;
    part_date    date;
    cutoff       date;
    dropped_cnt  integer := 0;
BEGIN
    IF retention_days IS NULL OR retention_days < 0 THEN
        retention_days := 30;
    END IF;
    cutoff := current_date - retention_days;
    FOR rec IN
        SELECT c.relname
        FROM pg_inherits i
        JOIN pg_class c       ON c.oid = i.inhrelid
        JOIN pg_class parent  ON parent.oid = i.inhparent
        WHERE parent.relname = 'syslog_entries'
          AND c.relname ~ '^syslog_entries_p[0-9]{8}$'
    LOOP
        BEGIN
            part_date := to_date(right(rec.relname, 8), 'YYYYMMDD');
        EXCEPTION WHEN others THEN
            CONTINUE;
        END;
        IF part_date < cutoff THEN
            EXECUTE format('DROP TABLE IF EXISTS %I', rec.relname);
            dropped_cnt := dropped_cnt + 1;
        END IF;
    END LOOP;
    RETURN dropped_cnt;
END;
$func$;

-- Pre-create today .. +7d of daily partitions.
SELECT ensure_syslog_partitions(7);

-- ---------------------------------------------------------------------------
-- 8. Re-apply grants + tamper-prevention revoke (the new parent is a fresh
--    object so grants must be re-applied; REVOKE cascades to partitions).
-- ---------------------------------------------------------------------------
GRANT ALL ON ALL TABLES IN SCHEMA public TO logvault_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO logvault_user;
GRANT EXECUTE ON FUNCTION ensure_syslog_partitions(integer)   TO logvault_user;
GRANT EXECUTE ON FUNCTION drop_old_syslog_partitions(integer) TO logvault_user;

REVOKE UPDATE, DELETE ON syslog_entries FROM logvault_user;

COMMIT;

-- ---------------------------------------------------------------------------
-- POST-MIGRATION:
--   * Restart services:  nssm start LogVault-Collector ; nssm start LogVault-API
--   * Sanity check:
--       SELECT count(*) FROM syslog_entries;                 -- includes legacy
--       SELECT relname FROM pg_inherits i
--         JOIN pg_class c ON c.oid = i.inhrelid
--         JOIN pg_class p ON p.oid = i.inhparent
--         WHERE p.relname = 'syslog_entries';                -- list partitions
--   * New rows get prev_hash/entry_hash; legacy rows stay NULL (expected).
-- ============================================================================


-- ============================================================================
-- ROLLBACK (manual — only if the migration must be reverted)
-- ============================================================================
-- Run as postgres. This restores the original single non-partitioned table.
-- NOTE: any rows ingested into NEW daily partitions AFTER the migration would
-- be lost by a naive rename-back; if any exist, copy them into the legacy table
-- first (see the optional COPY step). If you roll back immediately (no new
-- ingestion), the legacy table still holds all original rows.
--
--   BEGIN;
--
--   -- (Optional) preserve any post-migration rows that landed in daily/default
--   -- partitions before reverting:
--   --   INSERT INTO syslog_entries_legacy
--   --     (received_at, log_timestamp, source_ip, source_host, facility,
--   --      severity, severity_label, facility_label, vendor, program, pid,
--   --      message, raw_message, structured_data, is_parsed, parser_version,
--   --      category, risk_score, prev_hash, entry_hash)
--   --   SELECT received_at, log_timestamp, source_ip, source_host, facility,
--   --      severity, severity_label, facility_label, vendor, program, pid,
--   --      message, raw_message, structured_data, is_parsed, parser_version,
--   --      category, risk_score, prev_hash, entry_hash
--   --   FROM syslog_entries
--   --   WHERE received_at >= date_trunc('day', now());   -- post-cutover rows
--
--   -- Detach the legacy table from the partitioned parent.
--   ALTER TABLE syslog_entries DETACH PARTITION syslog_entries_legacy;
--
--   -- Drop the new partitioned parent (this drops the empty daily/default
--   -- partitions too; the sequence is OWNED BY it, so re-own it first).
--   ALTER SEQUENCE syslog_entries_id_seq OWNED BY NONE;
--   DROP TABLE syslog_entries;            -- partitioned parent + daily parts
--
--   -- Restore the legacy table as the canonical table.
--   ALTER TABLE syslog_entries_legacy DROP CONSTRAINT IF EXISTS syslog_entries_legacy_range;
--   ALTER TABLE syslog_entries_legacy RENAME TO syslog_entries;
--   ALTER TABLE syslog_entries ADD PRIMARY KEY (id);
--   ALTER SEQUENCE syslog_entries_id_seq OWNED BY syslog_entries.id;
--
--   -- Rename indexes back.
--   ALTER INDEX IF EXISTS idx_syslog_source_ip_legacy          RENAME TO idx_syslog_source_ip;
--   ALTER INDEX IF EXISTS idx_syslog_severity_legacy           RENAME TO idx_syslog_severity;
--   ALTER INDEX IF EXISTS idx_syslog_vendor_legacy             RENAME TO idx_syslog_vendor;
--   ALTER INDEX IF EXISTS idx_syslog_source_host_legacy        RENAME TO idx_syslog_source_host;
--   ALTER INDEX IF EXISTS idx_syslog_structured_legacy         RENAME TO idx_syslog_structured;
--   ALTER INDEX IF EXISTS idx_syslog_message_legacy            RENAME TO idx_syslog_message;
--   ALTER INDEX IF EXISTS idx_syslog_received_legacy           RENAME TO idx_syslog_received;
--   ALTER INDEX IF EXISTS idx_syslog_category_legacy           RENAME TO idx_syslog_category;
--   ALTER INDEX IF EXISTS idx_syslog_risk_score_legacy         RENAME TO idx_syslog_risk_score;
--   ALTER INDEX IF EXISTS idx_syslog_received_vendor_legacy    RENAME TO idx_syslog_received_vendor;
--   ALTER INDEX IF EXISTS idx_syslog_received_severity_legacy  RENAME TO idx_syslog_received_severity;
--   ALTER INDEX IF EXISTS idx_syslog_received_category_legacy  RENAME TO idx_syslog_received_category;
--   ALTER INDEX IF EXISTS idx_syslog_received_source_legacy    RENAME TO idx_syslog_received_source;
--   ALTER INDEX IF EXISTS idx_syslog_message_trgm_legacy       RENAME TO idx_syslog_message_trgm;
--   ALTER INDEX IF EXISTS idx_syslog_subcategory_legacy        RENAME TO idx_syslog_subcategory;
--
--   -- Restore app-role DML (original table allowed UPDATE/DELETE).
--   GRANT ALL ON syslog_entries TO logvault_user;
--
--   COMMIT;
-- ============================================================================
