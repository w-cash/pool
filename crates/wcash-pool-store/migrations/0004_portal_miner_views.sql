-- A winner exists as soon as a backend-validated share creates it. Give every
-- chain winner an immutable portal cursor so submitted blocks are visible
-- before reward allocation and dual-chain winners paginate independently.

ALTER TABLE winners
    ADD COLUMN portal_sequence BIGINT GENERATED ALWAYS AS IDENTITY;

CREATE UNIQUE INDEX winners_portal_sequence_idx
    ON winners(deployment_id, portal_sequence);

CREATE OR REPLACE FUNCTION preserve_winner_portal_sequence() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.portal_sequence IS DISTINCT FROM OLD.portal_sequence THEN
        RAISE EXCEPTION 'winner portal sequence is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER winners_portal_sequence_immutable
    BEFORE UPDATE ON winners
    FOR EACH ROW EXECUTE FUNCTION preserve_winner_portal_sequence();
