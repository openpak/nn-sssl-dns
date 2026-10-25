# Protocol: nn-sssl-dns

Fork of Pretendo's SSSL-DNS. Only the DNS half is used: it answers every Nintendo hostname
(and the `*.openpak.org` names the patched consoles use) with the OpenPak box, so a console
whose only knob is a DNS server setting (unmodded Wii U with an SSSL certificate, Wii, DS)
reaches OpenPak. TLS is terminated by OpenPak's Traefik, not by the nginx half. Image:
`ghcr.io/openpak/nn-sssl-dns` on tag; settings in `dns/example.env`.
