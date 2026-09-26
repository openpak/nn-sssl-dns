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

Profile names are answered only if they lie inside the Ed25519-signed ceiling fetched from `https://openpak.org/api/v1/network/ceiling` (union of the `switch`, `wiiu`, `3ds`, `wii` and `ds` families); names outside it are dropped one by one and logged. See [signed-ceiling.md](https://github.com/openpak/docs/blob/main/signed-ceiling.md).

These environment variables can be set manually or loaded from a `.env` file. See [example.env](./example.env) for an example configuration.

## Docker

The provided `Dockerfile` creates an image that runs the DNS server with Node.js. The configuration environment variables should either be provided to the container directly or mounted as a `.env` file in `/home/node/app/.env`. The [example Docker Compose file](../compose.yml) shows a setup that loads the configuration from a `.env` file in this directory.
