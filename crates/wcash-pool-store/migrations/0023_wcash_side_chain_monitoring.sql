-- Wcash proofs that are noncanonical or overtaken retain their exact witness
-- lifecycle without resubmission or reward credit. Existing rows, allocations,
-- and ledger entries are unchanged. Compatible binaries negotiate the required
-- wcash_winner_side_chain_v1 capability before exchanging mining work.
LOCK TABLE public.backend_cursors IN ACCESS EXCLUSIVE MODE;
ALTER TABLE public.winners DROP CONSTRAINT winners_side_chain_profile_check;
ALTER TABLE public.winner_proofs DROP CONSTRAINT winner_proofs_check;
