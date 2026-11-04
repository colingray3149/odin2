// Stand-in for OMP's stderr guard: the view has no native code writing to fd 2, so there is nothing to redirect.
export function suppressTerminalStderr(): void {}

export function restoreTerminalStderr(): void {}
