These tools are part of the [Dragonblood paper](https://papers.mathyvanhoef.com/dragonblood.pdf) titled "Dragonblood: A Security Analysis of WPA3's SAE Handshake".

# Prerequisites

## Compilation

Our scripts were tested on Kali Linux. To install the required dependencies on Kali, execute:

	apt-get update
	apt-get install autoconf automake libtool shtool libssl-dev pkg-config

After this, inside the repository directory compile our tools using:

	autoreconf -i
	./configure
	make

Remember to disable Wi-Fi in your network manager before using our scripts. After disabling Wi-Fi, execute `sudo rfkill unblock wifi` so our scripts can still use Wi-Fi.

## Required Wi-Fi Dongle and Configuration

Both the Dragondrain and Dragontime tool assume the [`ath_masker` kernel module](https://github.com/vanhoefm/ath_masker) is loaded. Because of this, both tools only support Atheros wireless cards. This is because both tools rely on the ability of the wireless card to acknowledge frames sent to spoofed MAC addresses. Currently we only implemented this acknowledgement functionality for Atheros cards.

After loading the `ath_masker` kernel module, and afterwards plugging in the Wi-Fi dongle, you need to put the interface into monitor mode:

	# Remember to first disable Wi-Fi in your network manager
	sudo rfkill unblock wifi
	sudo ifconfig wlan0 down
	sudo iw wlan0 set type monitor
	sudo ifconfig wlan0 up

Atheros devices we tested ourselves to work properly with the `ath_masker` kernel module are:
- **TODO: Amazon links**
- **TODO: Ask 3rd parties which tools they used**

Other Atheros devices that should work (but we did not explicitly test ourselves):
- **TODO: Amazon links**

So again, **remember to load [`ath_masker`](https://github.com/vanhoefm/ath_masker) before running Dragondrain and Dragontime**!

# Dragondrain: Clogging Attacks

The Dragondrain tool forges Commit messages to cause a high CPU usage on the target. This can for example be used to drain the battery of a device, or more generally to drain and exhaust resources.

## Quick start

1. First run `./dragondrain -d wlan0 -a 01:02:03:04:05:06 -c 6 -b 54 -n 1 -r 200` to test if it's possible to bypass anti-clogging, see "Common Usage" below for more details.
2. If that fails, run `./dragondrain -d wlan0 -a 01:02:03:04:05:06 -c 6 -b 54 -n 20 -r 200` while varying some parameters, and optionally trying curve P-521 by including parameter `-g 21`. See "Common Usage" below for more details.

## Basic Usage

For a list of all supported parameters, run `./dragondrain -h`. The only two required parameters are `-d` which specifies the wireless interface to use, and `-a` which specifies the MAC address of the Access Point to attack. For example:

	./dragondrain -d wlan0 -a 01:02:03:04:05:06

**Before running the tool, remember to first configure your Wi-Fi dongle (see "Required Wi-Fi Dongle and Configuration").** In practice you will also want to using the `-c` parameter to specify the channel of the AP, the `-b` parameter to select the bitrate used to inject frames, and the `-n` parameter to specify how many MAC addresses to spoof. We found that in practice, **some APs can only handle a small number of concurrently connected clients**, meaning most forged handshakes will fail. To prevent this, the adversary should only spoof a small number of MAC addresses for the attack to successfully overload the CPU of the victim. For example, to spoof 20 MAC addresses against an AP on channel 6 using a bitrate of 54, execute:

	./dragondrain -d wlan0 -a 01:02:03:04:05:06 -c 6 -b 54 -n 20

The tool will, for example, show the following output after executing this command:

	Opening card wlp0s20f0u9
	Setting to channel 1
	Will spoof MAC addresses in the form C4:E9:84:DB:FB:[00-13]
	Searching for AP ...
	Will forge 25 handshakes/second (1 commit every 0 sec 40 msec)
	[ STATUS: 20.80 forged handshakes/sec |  24 AC tokens received/sec |  49 commits sent/sec ]

From this we learn that the tool by default forges 25 handshakes per second. From the first number in the status line we learn that 20.80 handshakes are successfully forged per second. The other handshakes fail due to packet loss, or due to the AP dropping the handshake frames. The second number tells us that 24 Anti-Clogging tokens (AC tokens) are received (and hence also reflected) per second. Finally, we see that the tool is forging 49 commit frames per second.

## Common Usage

Building on the previous examples, we can tell the tool to forge more handshakes using the `-r` parameter. For example, to forge 200 handshakes per second (using 20 different MAC addresses), we use:

	./dragondrain -d wlan0 -a 01:02:03:04:05:06 -c 6 -b 54 -n 20 -r 200

**In most cases you will use the above commands, while varying the `-n`, `-r`, and `-b` parameters** depending on the target. If the target supports elliptic curve P-521, we can tell the tool to use this curve instead using the `-g 21` parameter. Because this is a bigger curve, we need to forge fewer handshakes to overload the AP:

	./dragondrain -d wlan0 -a 01:02:03:04:05:06 -c 6 -b 54 -n 20 -r 40 -g 21

Finally, **against several APs it is possible to bypass anti-clogging by forging all handshakes using the same MAC address**:

	./dragondrain -d wlan0 -a 01:02:03:04:05:06 -c 6 -b 54 -n 1 -r 200

Notice how in the above command the parameter `-n` equals 1, meaning only a single MAC address is spoofed to forge 200 handshakes per second. In case anti-clogging is successfully bypassed, you will see in the status line that many handshakes are forged, while (close to) zero anti-clogging tokens are received. Note that anti-clogging can only be bypassed if there are few "active" ongoing handshake. Practically, this mean you must wait a few minutes after performing a previous clogging attack before running the above command. Otherwise Hostapd will still require anti-clogging tokens, because it thinks old handshakes are still in progress.

## Specialized Usage

The development version of Hostapd contains a defense against our attack. To try to abuse this defense, include the `-M` parameter:

	./dragondrain -d wlan0 -a 01:02:03:04:05:06 -c 6 -g 19 -b 54 -n 1 -M

Once the tool detects that the queuing defense if Hostapd has been triggered, it will forge just enough handshakes per second such that the "handshake queue" at the AP remains full. As a result, no other client will be able to connect to the AP using WPA3. Note that this attack mode is experimental.

Another experimental attack mode involves sending a malformed commit frame after forging each handshake. This mode can be enabled by including the `-m` parameter. We conjecture that against some APs, this can be abused the bypass the anti-clogging defense.


# Dragontime

This is an experimental tool to carry out timing attacks against WPA3's SAE handshake. It was created to carry out attacks, not to detect whether an implementation is vulnerable in the first place. It was used to carry out the timing attack against MODP groups 22 and 24 as described in the [Dragonblood paper](https://papers.mathyvanhoef.com/dragonblood.pdf).

