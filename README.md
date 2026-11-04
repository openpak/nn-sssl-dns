# Console DNS Server

OpenPak's Console DNS Server.

| | |
| --- | --- |
| Network | Wii U, 3DS, Wii, DS, Switch |
| Role | DNS server for consoles whose only knob is a DNS setting: answers Nintendo hostnames with the OpenPak box, recurses other names only for consoles that already asked for an OpenPak name (everyone else is refused) |
| Depends on | OpenPak network profile and signed redirect ceiling on `openpak.org` (compiled-in list if unavailable); upstream resolver `1.1.1.1` by default |
| Image | `ghcr.io/openpak/nn-sssl-dns` |
| Based on | [Pretendo `SSSL-DNS`](https://github.com/PretendoNetwork/SSSL-DNS) (AGPL-3.0) |
| Licence | AGPL-3.0-only |

## What it serves

| Names | What |
| --- | --- |
| Nintendo hostnames, `*.openpak.org` | Answered with the OpenPak box |
| Names named by the network profile | Answered when inside the signed ceiling |
| Every other name | Recursed to the upstream resolver for known consoles; `REFUSED` for everyone else |

## Run

```sh
cp dns/example.env dns/.env   # set SSSL_DNS_DEFAULT_ADDRESS and the other values you need
docker compose up -d --build dns
```

## Docs

- [Protocol](docs/protocol.md)
- [Deploy](docs/deploy.md)
- [Provenance](docs/provenance.md)

## Licence

AGPL-3.0-only. See [LICENSE](LICENSE).

PRDs: openpak/prds (private)
