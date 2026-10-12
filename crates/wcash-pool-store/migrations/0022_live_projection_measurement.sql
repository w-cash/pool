-- Measurement evidence is separate from the accounting cursor. No historical
-- event is assigned an inferred mining acceptance time.
ALTER TABLE backend_cursors
    ADD COLUMN measurement_epoch UUID,
    ADD COLUMN live_observed_event_seq BIGINT CHECK (live_observed_event_seq >= 0),
    ADD COLUMN live_observed_at TIMESTAMPTZ,
    ADD COLUMN live_clean_since TIMESTAMPTZ,
    ADD COLUMN live_healthy BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT backend_measurement_epoch_nonzero CHECK (
        measurement_epoch IS NULL
        OR measurement_epoch <> '00000000-0000-0000-0000-000000000000'::UUID
    ),
    ADD CONSTRAINT backend_measurement_clean_interval CHECK (
        live_clean_since IS NULL
        OR (live_healthy AND live_observed_at IS NOT NULL
            AND live_clean_since <= live_observed_at)
    );
