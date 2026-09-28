/** Root layout; deliberately JSX-free so the fixture needs no React toolchain. */
export default function RootLayout(props: { children: unknown }): unknown {
  return props.children;
}
