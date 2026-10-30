declare module '@yarnpkg/lockfile' {
  const lockfile: {
    parse(text: string): { type: 'success' | 'merge' | 'conflict'; object: Record<string, unknown> };
  };
  export default lockfile;
}
