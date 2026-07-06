/**
 * Strip an optional "@version" suffix from an npm package spec, correctly
 * distinguishing it from npm's scope marker.
 *
 * A naive `name.split('@')[0]` breaks on SCOPED packages (`@scope/name`, e.g.
 * `@babel/core`, `@angular/common`) because they also start with '@' — that
 * split returns an empty string, silently breaking any package-name-keyed
 * lookup (known-CVE DB matches, browser-only-package checks, entry-point
 * priority boosts, …) for the entire scoped-package ecosystem.
 *
 * Only a LATER '@' (position > 0) is a version separator — a leading '@' at
 * position 0 is the scope marker and must be preserved.
 *
 * @param {string} spec - e.g. 'lodash', 'lodash@4.17.4', '@babel/core', '@babel/core@7.20.0'
 * @returns {string} the bare package name, scope included
 */
export function packageBaseName(spec) {
  if (!spec) return spec;
  const str = String(spec);
  const lastAt = str.lastIndexOf('@');
  return lastAt > 0 ? str.slice(0, lastAt) : str;
}
