# Protocol: nn-sssl-dns

Fork of Pretendo's SSSL-DNS. Only the DNS half is used: it answers every Nintendo hostname
(and the `*.openpak.org` names the patched consoles use) with the OpenPak box, so a console
whose only knob is a DNS server setting (unmodded Wii U with an SSSL certificate, Wii, DS)
reaches OpenPak. TLS is terminated by OpenPak's Traefik, not by the nginx half. Image:
`ghcr.io/openpak/nn-sssl-dns` on tag; settings in `dns/example.env`.

## Family list source

The family list is not a second source of truth. On boot, and again on the profile's
`recheck_after` hint, the resolver fetches `NETPROFILE_URL` (default: the website on this box,
`/api/v1/network/profile`) and answers exactly the families and exact names the profile names.
The compiled-in list covers the website being down: a console must never lose its name server
because a profile fetch failed. The profile's `redirect.never` is deliberately ignored: a
console whose only setting is a DNS server has no other resolver, and OpenPak's `conntest`
answer is the service, not a misdirected probe.
