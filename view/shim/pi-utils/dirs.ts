// Stand-in for OMP's `dirs`. Theme and log paths stay under Odin's state
// directory; profile and agent paths follow the pinned v18.13.2 contract
// (`~/.omp`, `OMP_PROFILE` / `PI_PROFILE`, `PI_CODING_AGENT_DIR`) so vendored
// keybinding inheritance resolves the same roots upstream does.
import * as os from "node:os";
import * as path from "node:path";

const CONFIG_DIR_NAME = ".omp";
const PROFILE_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const WINDOWS_RESERVED_BASENAME_RE = /^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?$/i;

export function getStateDir(): string {
	return path.join(process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state"), "odin");
}

export function getProjectDir(): string {
	return process.cwd();
}

/** Never created: the view ships only OMP's dark and light themes. */
export function getCustomThemesDir(): string {
	return path.join(getStateDir(), "view-themes");
}

export function getDebugLogPath(): string {
	return path.join(getStateDir(), "view-debug.log");
}

/**
 * Normalize and validate a profile name. Returns `undefined` for the implicit
 * default (empty string, whitespace, or the explicit "default" sentinel) and
 * throws for syntactically invalid or platform-reserved names.
 */
export function normalizeProfileName(profile: string | undefined): string | undefined {
	const normalized = profile?.trim();
	if (!normalized || normalized === "default") return undefined;
	if (
		normalized === "." ||
		normalized === ".." ||
		normalized.endsWith(".") ||
		!PROFILE_NAME_RE.test(normalized) ||
		WINDOWS_RESERVED_BASENAME_RE.test(normalized)
	) {
		throw new Error(
			`Invalid OMP profile "${profile}". Profile names must match ${PROFILE_NAME_RE.source}, ` +
				`cannot be "." or "..", cannot end with ".", and cannot be a Windows reserved device name ` +
				`(CON, PRN, AUX, NUL, COM0-9, LPT0-9, or any of those with an extension).`,
		);
	}
	return normalized;
}

function profileConfigRoot(profile: string | undefined): string {
	const root = path.join(os.homedir(), process.env.PI_CONFIG_DIR || CONFIG_DIR_NAME);
	return profile ? path.join(root, "profiles", profile) : root;
}

/** Invalid profile env must not crash a bare import; the default profile is used instead. */
function readProfileFromEnvSafe(value: string | undefined): string | undefined {
	try {
		return normalizeProfileName(value);
	} catch {
		return undefined;
	}
}

// Snapshotted at module load, as upstream's resolver is. The view never calls
// `setProfile` / `refreshDirsFromEnv`, so a later env edit is not observed.
const activeProfile = readProfileFromEnvSafe(
	process.env.OMP_PROFILE !== undefined ? process.env.OMP_PROFILE : process.env.PI_PROFILE,
);

function initialAgentDir(): string {
	if (activeProfile !== undefined) return path.join(profileConfigRoot(activeProfile), "agent");
	const agentDirEnv = process.env.PI_CODING_AGENT_DIR;
	const piProfile = readProfileFromEnvSafe(process.env.PI_PROFILE);
	// A value equal to a profile's derived agent dir was propagated by profile
	// activation, not chosen as the default-mode directory.
	if (piProfile !== undefined && agentDirEnv === path.join(profileConfigRoot(piProfile), "agent")) {
		return path.join(profileConfigRoot(undefined), "agent");
	}
	return agentDirEnv ? path.resolve(agentDirEnv) : path.join(profileConfigRoot(undefined), "agent");
}

const agentDir = initialAgentDir();

/** Get the active named profile. Undefined means the default profile. */
export function getActiveProfile(): string | undefined {
	return activeProfile;
}

/** Resolve the config root that backs a profile without activating it. */
export function getProfileRootDir(profile: string | undefined): string {
	return profileConfigRoot(normalizeProfileName(profile));
}

/** Get the agent config directory (`~/.omp/agent`, or the active profile / `PI_CODING_AGENT_DIR`). */
export function getAgentDir(): string {
	return agentDir;
}
