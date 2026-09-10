# OpenPak nn-sssl-dns — console DNS for OpenPak

Fork of Pretendo's SSSL-DNS. Only the DNS half is used: it answers every Nintendo hostname
(and the `*.openpak.org` names the patched consoles use) with the OpenPak box, so a console
whose only knob is a DNS server setting (unmodded Wii U with an SSSL certificate, Wii, DS)
reaches OpenPak. TLS is terminated by OpenPak's Traefik, not by the nginx half. Image:
`ghcr.io/openpak/nn-sssl-dns` on tag; settings in `dns/example.env`.

---

# SSSL DNS

This project contains a DNS server and a custom Nginx configuration intended to be used in conjunction with [SSSL](https://github.com/PretendoNetwork/SSSL).

## Usage

The provided [example Docker Compose file](./compose.yml) shows a setup that runs both the DNS server and Nginx together. Here's how to set it up:

1. Clone this repository: `git clone https://github.com/PretendoNetwork/SSSL-DNS.git`.
2. Use [SSSL](https://github.com/PretendoNetwork/SSSL) to create your own patched SSL certficiates.
3. Copy the `cert-chain.pem` and `ssl-cert-private-key.pem` from SSSL to the `nginx` directory in this repository.
4. Create an Nginx configuration file `nginx.conf` in the `nginx` directory. Check the [Nginx configuration README](./nginx/README.md) for more information.
5. Create a `.env` file in the `dns` directory. Check the [DNS server README](./dns/README.md) for more information.
6. Run `docker-compose up -d --build` to build and start your SSSL environment. This will take some time the first time you run it but will be faster on subsequent runs.
