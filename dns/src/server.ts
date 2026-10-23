import { createServer, Packet } from 'dns2';
import { table } from 'table';
import colors from '@colors/colors';
import dotenv from 'dotenv';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { Ceiling, CeilingStore, familiesFor, fetchCeilingBytes, filterProfile } from './ceiling';
import { NegativeCache, RateLimiter, configFromEnv, createHandler, formatStats, newStats, preserveEdnsSize, udpUpstream } from './guard';

process.on('SIGTERM', () => {
	process.exit();
});

dotenv.config();

const addressMap: Record<string, string> = {};

for (const variable in process.env) {
	if (variable.startsWith('SSSL_DNS_MAP')) {
		const hostname = variable.split('SSSL_DNS_MAP_')[1];
		const address = process.env[variable]!;

		addressMap[hostname] = address;
	}
}

if (!addressMap['conntest.nintendowifi.net']) {
	if (!process.env.SSSL_DNS_DEFAULT_ADDRESS) {
		console.log(colors.bgRed('Mapping for conntest.nintendowifi.net not found and no default address set. Set either SSSL_DNS_DEFAULT_ADDRESS or SSSL_DNS_MAP_conntest.nintendowifi.net'));
		process.exit();
	}

	addressMap['conntest.nintendowifi.net'] = process.env.SSSL_DNS_DEFAULT_ADDRESS;
}

if (!addressMap['account.nintendo.net']) {
	if (!process.env.SSSL_DNS_DEFAULT_ADDRESS) {
		console.log(colors.bgRed('Mapping for account.nintendo.net not found and no default address set. Set either SSSL_DNS_DEFAULT_ADDRESS or SSSL_DNS_MAP_account.nintendo.net'));
		process.exit();
	}

	addressMap['account.nintendo.net'] = process.env.SSSL_DNS_DEFAULT_ADDRESS;
}

let udpPort = 0;
let tcpPort = 0;

if (process.env.SSSL_UDP_PORT) {
	udpPort = Number(process.env.SSSL_UDP_PORT);
}

if (process.env.SSSL_TCP_PORT) {
	tcpPort = Number(process.env.SSSL_TCP_PORT);
}

if (Number.isNaN(udpPort)) {
	console.log(colors.bgRed('Invalid UDP port'));
	process.exit();
}

if (Number.isNaN(tcpPort)) {
	console.log(colors.bgRed('Invalid TCP port'));
	process.exit();
}

if (udpPort === 0 && tcpPort === 0) {
	console.log(colors.bgRed('No server port set. Set one of SSSL_UDP_PORT or SSSL_TCP_PORT'));
	process.exit();
}

if (udpPort === tcpPort) {
	console.log(colors.bgRed('UDP and TCP ports cannot match'));
	process.exit();
}

if (udpPort === 0) {
	console.log(colors.bgYellow('UDP port not set. One will be randomly assigned'));
}

if (tcpPort === 0) {
	console.log(colors.bgYellow('TCP port not set. One will be randomly assigned'));
}

// OpenPak (NP-4): the families this resolver answers are the same list the
// emulators read — GET /api/v1/network/profile on the website, fetched on
// boot and re-fetched on the profile's own recheck_after hint. Until the
// first fetch lands, and again whenever the website stops answering, the
// last applied list keeps serving (stale beats broken: a console must never
// lose its name server because a profile fetch failed).
//
// Signed ceiling (docs/signed-ceiling.md): every profile name must lie inside
// the Ed25519-signed ceiling fetched from openpak.org; names outside it are
// dropped one by one and logged, never the whole profile. The compiled list
// below is only the first-boot fallback ceiling, used while no verified
// ceiling has ever been cached. It is never updated again.
const OURS_FALLBACK = ['.nintendo.net', '.nintendowifi.net', '.nintendo.com', '.openpak.org', '.gamespy.com', '.battle.net'];
let oursSuffixes = OURS_FALLBACK;
let oursExact: string[] = [];
let recheckAfter = 6 * 3600; // seconds; replaced by the profile's own hint
const NETPROFILE_URL = process.env.NETPROFILE_URL || 'http://127.0.0.1:20010/api/v1/network/profile';
const ceilingStore = new CeilingStore(process.env.SSSL_DNS_STATE_DIR || join(homedir(), '.openpak-sssl-dns'));
let lastProfile: { suffixes: unknown[]; exact: unknown[] } | undefined;
let lastCeilingError = '';

function ceilingFamilies(): string[] {
	return ceilingStore.current ? familiesFor(ceilingStore.current) : OURS_FALLBACK;
}

function logCeilingError(reason: string): void {
	// Once per distinct reason: a six-hourly tick must not repeat itself.
	if (reason !== lastCeilingError) {
		lastCeilingError = reason;
		console.log(colors.yellow(`signed ceiling rejected (${reason}); keeping ${ceilingStore.current ? `v${ceilingStore.current.version}` : 'the compiled-in fallback'}`));
	}
}

function loadCachedCeiling(): void {
	try {
		const ceiling = ceilingStore.loadCached();
		console.log(colors.green(`cached ceiling v${ceiling.version} loaded: ${familiesFor(ceiling).length} families`));
	} catch (err) {
		console.log(colors.yellow(`${err instanceof Error ? err.message : String(err)}; ceiling is the compiled-in fallback until a signed one verifies`));
	}
}

async function refreshCeiling(): Promise<void> {
	const before = ceilingFamilies().join(' ');
	const previous = ceilingStore.current?.version;
	let ceiling: Ceiling;
	try {
		ceiling = ceilingStore.accept(await fetchCeilingBytes());
	} catch (err) {
		logCeilingError(err instanceof Error ? err.message : String(err));
		return;
	}
	lastCeilingError = '';
	const after = ceilingFamilies().join(' ');
	if (previous !== ceiling.version || before !== after) {
		console.log(colors.green(`ceiling v${ceiling.version} accepted: ${familiesFor(ceiling).length} families`));
		if (before !== after) {
			console.log(colors.green(`ceiling families changed: ${after}`));
		}
	}
}

function applyProfile(): void {
	// No profile yet: the compiled list serves, still clipped to the ceiling.
	const profile = lastProfile ?? { suffixes: OURS_FALLBACK, exact: [] };
	const filtered = filterProfile(profile.suffixes, profile.exact, ceilingFamilies());
	for (const name of filtered.dropped) {
		console.log(colors.yellow(`profile name outside the signed ceiling dropped: ${name}`));
	}
	oursSuffixes = filtered.suffixes;
	oursExact = filtered.exact;
}

// A console whose only network setting is a DNS server has nowhere else to
// go, so this resolver answers every name the profile names — including ones
// the profile lists under redirect.never. That list exists for clients with
// a working resolution path of their own (emulators): a connection test
// pointed at OpenPak measures OpenPak. Here the alternative to answering
// conntest is forwarding it to a corpse, and the console has no second
// resolver to fall back to. OpenPak's answer IS the service.
interface NetworkProfile {
	version?: number;
	server?: { address?: string };
	redirect?: { suffixes?: unknown; exact?: unknown };
	recheck_after?: number;
}

async function fetchProfile(): Promise<void> {
	const res = await fetch(NETPROFILE_URL, { signal: AbortSignal.timeout(2000) });
	if (!res.ok) {
		throw new Error(`profile fetch answered ${res.status}`);
	}
	const profile = await res.json() as NetworkProfile;
	const suffixes = profile.redirect?.suffixes;
	const exact = profile.redirect?.exact;
	// A profile without its lists is no profile; a bad entry inside them is
	// only that entry, dropped by the ceiling filter.
	if (!Array.isArray(suffixes) || !Array.isArray(exact)) {
		throw new Error('profile carries no redirect lists');
	}
	lastProfile = { suffixes, exact };
	applyProfile();
	if (typeof profile.recheck_after === 'number' && profile.recheck_after > 0) {
		recheckAfter = profile.recheck_after;
	}
	console.log(colors.green(`network profile applied: version ${profile.version ?? '?'}, ${oursSuffixes.length} families, ${oursExact.length} exact names, recheck ${recheckAfter}s`));
}

// Ceiling, then profile: once at boot (fallbacks cover failure), then on the
// profile's own hint. A list that changes a few times a month does not want a
// push channel; a missed refresh only means the console keeps yesterday's
// correct answer.
async function refresh(): Promise<void> {
	await refreshCeiling();
	try {
		await fetchProfile();
	} catch (err) {
		// The ceiling may still have narrowed: re-filter what is serving.
		applyProfile();
		throw err;
	}
}

async function profileLoop(): Promise<void> {
	loadCachedCeiling();
	try {
		await refresh();
	} catch (err) {
		console.log(colors.yellow(`network profile unavailable; keeping the last applied list (${String(err)})`));
	}
	const tick = (): void => {
		refresh().catch(() => { /* the last good list is already serving */ });
	};
	setInterval(tick, Math.max(recheckAfter, 60) * 1000).unref();
}

const DEFAULT_ADDRESS = process.env.SSSL_DNS_DEFAULT_ADDRESS;

function ours(name: string): string | undefined {
	if (addressMap[name]) {
		return addressMap[name];
	}
	const lower = name.toLowerCase();
	if (!DEFAULT_ADDRESS) {
		return undefined;
	}
	if (oursSuffixes.some(suffix => lower.endsWith(suffix)) || oursExact.includes(lower)) {
		return DEFAULT_ADDRESS;
	}
	return undefined;
}

// OpenPak: this resolver is reachable from the internet, because a console's DNS setting is
// the only one it has. Rate limiting, refused types, the UDP size clamp and the negative cache
// live in guard.ts; settings in dns/README.md.
const guardConfig = configFromEnv(process.env);
preserveEdnsSize(Packet as never);
const limiter = new RateLimiter(guardConfig);
const stats = newStats();
const handle = createHandler({
	Packet: Packet as never,
	config: guardConfig,
	ours,
	upstream: udpUpstream(Packet as never, process.env.SSSL_DNS_UPSTREAM || '1.1.1.1', 53, guardConfig.upstreamTimeoutMs),
	limiter,
	negative: new NegativeCache(guardConfig.negativeTtl),
	stats
});

setInterval(() => limiter.sweep(), 60_000).unref();

// Aggregate counters only: no client address is ever logged.
let lastStats = '';
function logStats(): void {
	const line = formatStats(stats);
	if (line !== lastStats) {
		lastStats = line;
		console.log(`dns stats (since start): ${line}`);
	}
}
if (guardConfig.statsInterval > 0) {
	setInterval(logStats, guardConfig.statsInterval * 1000).unref();
}
process.on('SIGUSR2', logStats);

const server = createServer({
	udp: true,
	tcp: true,
	handle: (request, send, rinfo) => {
		handle(request, send, rinfo).catch(() => {
			stats.malformed += 1;
		});
	}
});

server.on('listening', () => {
	const tableConfig = {
		border: {
			topBody: '─',
			topJoin: '┬',
			topLeft: '┌',
			topRight: '┐',

			bottomBody: '─',
			bottomJoin: '┴',
			bottomLeft: '└',
			bottomRight: '┘',

			bodyLeft: '│',
			bodyRight: '│',
			bodyJoin: '│',

			joinBody: '─',
			joinLeft: '├',
			joinRight: '┤',
			joinJoin: '┼'
		}
	};

	const addresses = server.addresses();
	const tableData = [
		[colors.cyan('Protocol'), colors.cyan('Address')]
	];

	if (addresses.udp) {
		tableData.push([
			colors.green('UDP'), colors.green(`${addresses.udp.address}:${addresses.udp.port}`)
		]);
	}

	if (addresses.tcp) {
		tableData.push([
			colors.green('TCP'), colors.green(`${addresses.tcp.address}:${addresses.tcp.port}`)
		]);
	}

	console.log(colors.green('SSSL-DNS listening on the following addresses'));
	console.log(table(tableData, tableConfig));
});

// SSSL_BIND_ADDRESS: bind one interface (a host with systemd-resolved on 127.0.0.53 cannot take 0.0.0.0:53).
const bindAddress = process.env.SSSL_BIND_ADDRESS || '0.0.0.0';
server.listen({
	udp: udpPort !== 0 ? { port: udpPort, address: bindAddress } : undefined,
	tcp: tcpPort !== 0 ? { port: tcpPort, address: bindAddress } : undefined
} as never); // dns2 accepts { port, address } at runtime; its typings only know a port

void profileLoop();
