export const nested = (
  x: (inner: (y: string) => number) => boolean
) => (z: boolean) => (w: string) => x((y) => y.length);

export function Icon(props: { label: string }) {
  return <span>{props.label}</span>;
}
