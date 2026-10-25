# Notes: nn-sssl-dns

Since NP-4 ([PRD `website/prds/network-profile-service-prd.md`](../../../../core/infra/website/prds/network-profile-service-prd.md)) the family list is not a second source of
truth: on boot, and again on the profile's `recheck_after` hint, the resolver fetches
`NETPROFILE_URL` (default: the website on this box, `/api/v1/network/profile`) and answers
exactly the families and exact names the profile names. The compiled-in list covers the
website being down — a console must never lose its name server because a profile fetch
failed. The profile's `redirect.never` is deliberately ignored here: a console whose only
setting is a DNS server has no other resolver, and OpenPak's `conntest` answer is the
service, not a misdirected probe.
