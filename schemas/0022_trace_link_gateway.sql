ALTER TABLE trace_calls ADD COLUMN served_model TEXT;
ALTER TABLE trace_calls ADD COLUMN model_group TEXT;
ALTER TABLE trace_calls ADD COLUMN attempted_fallbacks INTEGER;
ALTER TABLE trace_calls ADD COLUMN gateway_call_id TEXT;
-- Header string from x-litellm-response-cost when that header is present.
-- Streaming responses omit it; export never copies a request model into it.
ALTER TABLE trace_calls ADD COLUMN response_cost TEXT;
