- **Cleared all 8 known npm advisories in the repo's JS tooling lockfiles.** The
  docs site moves to Astro 7 (fixes GHSA-2pvr-wf23-7pc7, GHSA-8hv8-536x-4wqp,
  GHSA-j687-52p2-xcff, GHSA-jrpj-wcv7-9fh9, GHSA-xr5h-phrj-8vxv and the
  transitive esbuild GHSA-g7r4-m6w7-qqqr), and the puppeteer test harness picks
  up patched `js-yaml`/`ws` (GHSA-h67p-54hq-rp68, GHSA-96hv-2xvq-fx4p).
  Dependabot now watches all three npm lockfile directories so advisories can
  no longer accumulate silently, and the README carries the live OpenSSF Best
  Practices (Passing) badge (#407).
