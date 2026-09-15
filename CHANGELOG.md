# Changelog — nn-sssl-dns

Generated from git history on 2026-09-15. `git log` stays the source
of truth; this file is the readable summary.

## v0.2.0 — 2026-09-11



## v0.1.3 — 2026-09-10



## v0.1.2 — 2026-09-10



## v0.1.1 — 2026-09-10



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

