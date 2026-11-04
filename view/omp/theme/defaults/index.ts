// odin: changed from OMP 2a2c6dc — the view ships one extra theme, the Cyber Blossom palette (`src/cyber-blossom.json`),
// instead of OMP's 100 bundled themes; dark and light still come from theme/dark.json and theme/light.json.
import cyberBlossom from "../../../src/cyber-blossom.json" with { type: "json" };

export const defaultThemes = { "cyber-blossom": cyberBlossom };
