# Changelog — nn-sssl-dns

Generated from git history on 2026-09-15. `git log` stays the source
of truth; this file is the readable summary.

## Unreleased

- **Abuse limits for the public resolver** (`dns/src/guard.ts`, settings in `dns/README.md`):
  per-prefix rate limiting (/24, /56) with BIND-style slip, `ANY` refused everywhere, TXT,
  DNSSEC types, zone transfers and non-IN classes refused on recursion, UDP answers clamped to
  1232 bytes (512 without EDNS) and stripped to the answer section, a 30 s negative cache,
  an upstream timeout, aggregate counters only. Nintendo-name answers unchanged byte for byte.
  A packet without a question no longer crashes the process.

## v0.5.0 — 2026-10-16

- Answers the ps3 platform's families (.playstation.net/.org/.com,
  .sonyentertainmentnetwork.com) for real PS3s and Pier, inside signed ceiling v11.
- ci: build scratch in the runner temp, not the checkout [1fba45c]; docs commits

## v0.4.0 — 2026-09-24

- **Signed redirect ceiling.** Profile names are answered only inside the Ed25519-signed ceiling
  from `https://openpak.org/api/v1/network/ceiling` (verified against pinned keys, rollback
  refused, cached in `SSSL_DNS_STATE_DIR`). Until that endpoint answers, the compiled family
  list is the ceiling, as before.
- Dependencies: typescript-eslint 8, eslint 8.57, TypeScript 5.9; npm audit clean.
- The image builds on OpenPak's self-hosted runner with podman; the repo is private.
- `.battle.net` added to the compiled fallback families [4af27ac]; README links the NP PRD
  in the website repo; CI builds only on `v*.*.*` tags [1fbc8d8].

## v0.3.0 — 2026-09-12

- NP-4: read the same map the emulators read — the website's network profile
  (`NETPROFILE_URL`) decides the answered families and names; the compiled suffix list is
  fallback only [95728a4]
- Drop upstream's two image workflows: release.yml builds the image OpenPak deploys [dccfabd]

## v0.2.0 — 2026-09-11

- Rate limit and refuse ANY: this resolver is reachable from the internet [2025b3f]

## v0.1.3 — 2026-09-10

- listen options cast: dns2 takes `{ port, address }` at runtime [80dc9c0]

## v0.1.2 — 2026-09-10

- `SSSL_BIND_ADDRESS`: bind one interface, for hosts where systemd-resolved owns
  127.0.0.53:53 [b5a6400]

## v0.1.1 — 2026-09-10

- A whole resolver, not a map: Nintendo and openpak.org names answer with the OpenPak box,
  everything else is forwarded upstream [37a6383]

## v0.1.0 — 2026-09-10



## v0.1.0 — 2026-09-10

- OpenPak: DNS server image on tag, OpenPak addresses, nginx half unused [733bc2a]
- Merge pull request #5 from mrjvs/master [f72e4bc]
- Add org prefix [12776e8]
- checkout code manually [590cd68]
- Fix mistake in CI [22633f6]
- Merge pull request #4 from mrjvs/master [4ccf702]
- Add CI [772ac70]
- Merge pull request #2 from MatthewL246/separate-containers [b458efe]
- chore: stop unnecessarily adding OpenSSL to LD_LIBRARY_PATH [bdb637e]
- chore: remove unnecessary OpenSSL compilation [9c50898]
- chore: switch to Ubuntu 24.04 [2643f67]
- chore: switch from pm2 to node [c49fece]
- chore: disable nginx HTTP rewrites to reduce image size [331cf24]
- chore: disable unnecessary newer TLS versions [181c600]
- chore: un-hardwrap readme lines [c517c0a]
- fix: prevent container stop from timing out [c446e4e]
- docs: improve wording for Nginx configuration [bee33c2]
- fix: broken relative link [88d6b41]
- docs: update documentation for new setup [84f2bef]
- chore: add app directory argument to DNS Dockerfile [b1f8b98]
- chore: move Nginx config to a separate container [c6b5ab0]
- chore: move the DNS server to a separate container [8fc66b1]
- rename nginx.conf to nginx.example.conf [736ed58]
- move log config to http block [731d863]
- swap example servers back to IPs rather than domains [8153519]
- conntest is http only [e765d7f]
- split nginx.conf into separate servers [48ed7bd]
- replace spaces with tabs [a53821f]
- add Docker guide to README [980a335]
- added port warnings [e11448b]
- remove DoH. Wii U doesnt support it [a3391e5]
- replace 4 spaces with tabs in Dockerfile [1a73649]
- add the ability to change ports [5662ed0]
- added Dockerfile [7beed79]
- update: remove unused comment and rename config to tableConfig [b3a8654]
- patch: update config settings in README [a3216b9]
- added DNS server [052cc0d]

