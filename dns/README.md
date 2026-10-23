# SSSL DNS server

Custom DNS server intended to be used in conjunction with [SSSL](https://github.com/PretendoNetwork/SSSL). It redirects Nintendo hostnames to an SSSL-powered server using DNS spoofing.

## Config

The only 2 addresses required are for `conntest.nintendowifi.net` and `account.nintendo.net`. These can either be set using the default address or explicitly mapping them. Additional addresses may be added using `SSSL_DNS_MAP`.

| Name                       | Description                                                                            | Required                               |
| -------------------------- | -------------------------------------------------------------------------------------- | -------------------------------------- |
| `SSSL_UDP_PORT`            | UDP port for the DNS server.                                                           | Only if not using TCP.                 |
| `SSSL_TCP_PORT`            | TPC port for the DNS server.                                                           | Only if not using UDP.                 |
| `SSSL_DNS_DEFAULT_ADDRESS` | The default address to use for `conntest.nintendowifi.net` and `account.nintendo.net`. | Only if not explicitly mapped.         |
| `SSSL_DNS_MAP_hostname`    | An explicit mapping of a hostname to an address.                                       | Only if not using the default address. |
| `NETPROFILE_URL`           | OpenPak network profile to answer (default: the website on this box).                  | No.                                    |
| `SSSL_DNS_STATE_DIR`       | Where the signed ceiling and its highest accepted version persist (default `~/.openpak-sssl-dns`). | No.                     |
| `SSSL_DNS_UPSTREAM`        | Upstream resolver for every name that is not OpenPak's (default `1.1.1.1`).            | No.                                    |
| `SSSL_BIND_ADDRESS`        | Interface to bind (default `0.0.0.0`).                                                 | No.                                    |

### Abuse limits (OpenPak)

The resolver is reachable from the internet, so it guards against being used as a DDoS amplifier
(`src/guard.ts`). Defaults are sized for consoles, which make a few dozen queries at boot.

| Name                           | Default | What it does |
| ------------------------------ | ------- | ------------ |
| `SSSL_DNS_RATE`                | `20`    | Queries per second each source prefix may make over UDP (token-bucket refill). |
| `SSSL_DNS_BURST`               | `200`   | Bucket size: a boot, or several consoles behind one address, fits comfortably. |
| `SSSL_DNS_SLIP`                | `2`     | Over the limit, every Nth query gets an empty truncated (TC=1) answer, the rest are dropped. `0` drops all. |
| `SSSL_DNS_IPV4_PREFIX`         | `24`    | IPv4 prefix length that shares one bucket. |
| `SSSL_DNS_IPV6_PREFIX`         | `56`    | IPv6 prefix length that shares one bucket. |
| `SSSL_DNS_MAX_BUCKETS`         | `100000`| Prefixes tracked at once; past this, new prefixes share one bucket until idle ones are swept (60 s). |
| `SSSL_DNS_MAX_UDP`             | `1232`  | Largest UDP answer, whatever EDNS size the client asks for (512 without EDNS). Bigger answers go out empty with TC=1. |
| `SSSL_DNS_NEGATIVE_TTL`        | `30`    | Seconds an upstream failure (timeout, SERVFAIL) or NXDOMAIN is cached per name and type. `0` disables. |
| `SSSL_DNS_UPSTREAM_TIMEOUT_MS` | `2000`  | Upstream query timeout; the client then gets SERVFAIL. |
| `SSSL_DNS_STATS_INTERVAL`      | `3600`  | Seconds between aggregate counter lines in the log (only when something changed); `SIGUSR2` prints one now. `0` disables. No client address is ever logged. |

Rules:

- **Rate limit, UDP only.** TCP needs a handshake, so it cannot be spoofed and is not limited. Over the
  limit the resolver follows BIND's response-rate-limiting "slip": dropping makes the resolver
  useless as a reflector, and the occasional truncated answer (no larger than the query) tells a
  real client behind an abused prefix to retry over TCP. TCP 53 must be published for that retry to work.
- **Refused types.** `ANY` is refused for every name. For names that are not OpenPak's, recursion also
  refuses `TXT`, `SPF`, `NULL`, the DNSSEC types (`DS`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`,
  `DNSKEY`, `CDS`, `CDNSKEY`), zone transfers (`AXFR`, `IXFR`) and `MAILA`/`MAILB`, as well as non-`IN`
  classes (CHAOS `version.bind`) and non-`QUERY` opcodes (NOTIMP). Refusals echo the question and
  nothing else. Consoles only ask for `A`; `AAAA`, `CNAME`, `SRV`, `MX`, `PTR`, `NS`, `SOA`, `CAA`
  and other types are still recursed.
- **Nintendo and OpenPak names** get the same answer as before, byte for byte: `A` with the OpenPak
  address, an empty `NOERROR` for other types.
- **Recursive answers** carry the answer section only (no authority or additional records), keep the
  upstream rcode (an upstream timeout is now `SERVFAIL`, not an empty `NOERROR`), and over UDP
  advertise 1232 bytes when the client used EDNS. Each query type is forwarded as itself (types dns2
  cannot name used to be forwarded as `A`); answer records dns2 cannot re-encode are left out.

Profile names are answered only if they lie inside the Ed25519-signed ceiling fetched from `https://openpak.org/api/v1/network/ceiling` (union of the `switch`, `wiiu`, `3ds`, `wii` and `ds` families); names outside it are dropped one by one and logged. See [signed-ceiling.md](https://github.com/openpak/docs/blob/main/signed-ceiling.md).

These environment variables can be set manually or loaded from a `.env` file. See [example.env](./example.env) for an example configuration.

## Docker

The provided `Dockerfile` creates an image that runs the DNS server with Node.js. The configuration environment variables should either be provided to the container directly or mounted as a `.env` file in `/home/node/app/.env`. The [example Docker Compose file](../compose.yml) shows a setup that loads the configuration from a `.env` file in this directory.
