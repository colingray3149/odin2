-- When a store claimed a generation: a copy that never sealed is swept a day
-- later. When the store first found the generation's source unwired:
-- retention releases it only after several days unwired.
ALTER TABLE brain_generation
    ADD COLUMN claimed_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN unwired_since timestamptz;
