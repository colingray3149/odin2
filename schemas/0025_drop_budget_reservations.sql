-- Migration 25: the budget reservation table is gone; no code reads or writes it.

DROP INDEX IF EXISTS budget_reservations_account;
DROP TABLE IF EXISTS budget_reservations;
