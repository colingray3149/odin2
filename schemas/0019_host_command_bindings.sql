CREATE TABLE host_command_bindings (
  command_id TEXT PRIMARY KEY REFERENCES commands(command_id) ON DELETE CASCADE,
  binding_json TEXT NOT NULL CHECK(json_valid(binding_json) AND json_type(binding_json) = 'object')
) STRICT;
