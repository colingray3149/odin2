// Stand-in for the `@oh-my-pi/pi-ai` names the vendored TUI imports.
// ImageContent matches OMP v18.13.2 `packages/ai/src/types.ts`.

/** Provider-native uploaded file reference for image reuse without retransmitting bytes. */
export interface ProviderFileReference {
	provider: "openai" | "anthropic" | "google";
	id?: string;
	uri?: string;
	expiresAt?: number;
}

export interface ImageContent {
	type: "image";
	/** Base64 encoded image data. */
	data: string;
	/** e.g. "image/jpeg", "image/png". */
	mimeType: string;
	/**
	 * OpenAI-only resolution hint. `"original"` preserves native resolution.
	 * Providers without a detail knob ignore it.
	 */
	detail?: "auto" | "low" | "high" | "original";
	/** Provider-native file reference preferred only by its matching provider. */
	providerFile?: ProviderFileReference;
	/**
	 * Optional https mirror of `data`. `data` remains the source of truth.
	 */
	url?: string;
}
