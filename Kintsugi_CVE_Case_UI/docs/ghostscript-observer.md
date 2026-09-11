# Ghostscript container observation UI

This local presentation uses the existing experiment report; it does not query Docker or execute attacks.

## Components

- `app/ghostscript-observation.mjs`: pure four-step state model; keeps report evidence and mechanism illustrations separate.
- `app/ghostscript-observer.tsx`: directory-focused observation window reused in location and comparison views.
- `app/ghostscript-observer.css`: scoped presentation styles and responsive layout.
- `app/sample-viewer.tsx`: bundled normal, malicious and post-repair malicious scenario buttons. The latter two read the same sample file.

## Evidence boundaries

- Normal HTTP 200 / 1653 bytes and malicious HTTP 500 / marker absent come from Stage 10 of `CVE-2018-16509-report.md`.
- Attack marker presence and normal directory absence are mechanism illustrations, not captured filesystem snapshots.
- Process relationships are schematic. No PID, timestamp or syscall count is invented.
- The validated repair uses an EPS input guard, not verified kernel eBPF enforcement.
- Missing before-repair stat output, returned image and filesystem metadata are not synthesized.

Each scenario clears the previous display before advancing. The repair flag is scoped to the selected demonstration and does not change the backend. Regular uploads still inspect file bytes.

## Verification

`npm test` covers evidence timing, provenance and legitimate EPS interpreter use. Build and TypeScript checks validate integration. Browser checks cover switching all three sample scenarios, synchronized comparison and opening file evidence. No experiment/container state is modified by these checks.
