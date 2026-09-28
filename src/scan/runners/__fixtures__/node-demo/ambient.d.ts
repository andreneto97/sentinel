// The fixture repository exists to be *analysed*, not compiled against a real
// package: knip reports `not-a-listed-package` as an undeclared dependency, and
// this shorthand declaration keeps `tsc --noEmit` green without adding it.
declare module "not-a-listed-package";
