#!/usr/bin/env python3

# wifijam -- An 802.11n beacon frame transmission program
# Copyright (C) 2017  Star Brilliant <m13253@hotmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import random
import scapy.all as scapy
import subprocess
import struct
import sys
import time


BEACON_INTERVAL = 100
ssid_list = [
    # No-break space - Face with tears of joy
    '\u00a0\U0001f602',
]

SSID_DUPLICATES = 10
ssid_suffixes = [
    # Empty
    '',
    # Soft hyphen
    '\u00ad',
    # Zero width space
    '\u200b',
    # Zero width non-joiner
    '\u200c',
    # Zero width joiner
    '\u200d',
    # Word joiner
    '\u2060',
    # Function application
    '\u2061',
    # Invisible times
    '\u2062',
    # Invisible separator
    '\u2063',
    # Invisible plus
    '\u2064',
]

beacon_header = bytes([
    # 0x00: Frame control field
    0x80, 0x00,
    # 0x02: Duration: 0 microseconds
    0x00, 0x00,
    # 0x04: Receiver address: Broadcast
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    # 0x0a: Transmitter address: Random
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    # 0x10: BSSID: Random
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    # 0x16: Sequence number (12 bits), fragment number (4 bits)
    0x00, 0x00,

    # 0x18: Timestamp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    # 0x20: Beacon interval (times 1.024 ms)
    0x64, 0x00,
    # 0x22: Capabilities: ESS, WEP, Short Preamble, Short Slot Time
    0x31, 0x04,
    # 0x24: SSID parameter set
    0x00, 0x00,
    # 0x26
])

beacon_tail = bytes([
    # 0x00: Supported rates: 1M, 2M, 5.5M, 11M, 6M, 9M, 12M, 18M
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
    # 0x0a: Current channel: Random
    0x03, 0x01, 0x00,
    # 0x0d: RSN Information: WPA2
    0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
    0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
    0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
    # 0x23: Extended supported rates: 24M, 36M, 48M, 54M
    0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
    # 0x29: HT Information
    0x3d, 0x16, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    # 0x41
])


class StationInfo:
    pass


def get_string_length_with_limit(s, limit=32):
    byte_len = 0
    rune_len = 0
    while byte_len <= limit:
        if byte_len == len(s):
            return byte_len
        if s[byte_len] & 0xc0 != 0x80:
            rune_len = byte_len
        byte_len += 1
    return rune_len


def create_beacon_packet(station_info):
    ssid_len = get_string_length_with_limit(station_info.ssid)
    suffix_len = get_string_length_with_limit(station_info.ssid_suffix, 32 - ssid_len)
    packet = []
    packet += beacon_header
    packet[0x0a:0x10] = station_info.bssid[:6]
    packet[0x10:0x16] = station_info.bssid[:6]
    packet[0x16] = (station_info.sequence << 4) & 0xf0
    packet[0x17] = (station_info.sequence >> 4) & 0xff
    station_info.sequence = (station_info.sequence + 1) & 0xfff
    packet[0x18] = random.randint(0, 0xff)
    packet[0x19] = random.randint(0, 0xff)
    packet[0x1a] = random.randint(0, 0xff)
    packet[0x1b] = random.randint(0, 0xff)
    packet[0x1c] = random.randint(0, 0xff)
    packet[0x20] = BEACON_INTERVAL & 0xff
    packet[0x21] = (BEACON_INTERVAL >> 8) & 0xff
    packet[0x25] = (ssid_len + suffix_len) & 0xff
    packet += station_info.ssid[:ssid_len]
    packet += station_info.ssid_suffix[:suffix_len]
    packet += beacon_tail
    packet[0x26 + ssid_len + suffix_len + 0x0c] = station_info.channel & 0xff;
    packet[0x26 + ssid_len + suffix_len + 0x2b] = station_info.channel & 0xff;
    packet[0x26 + ssid_len + suffix_len + 0x2c] = 0x4 | (station_info.sub_channel & 0x3);
    return bytes(packet)


def initialize_stations(ssid_list, ssid_suffixes, ssid_duplicates):
    station_info = []
    for suffix in ssid_suffixes[:ssid_duplicates]:
        for ssid in ssid_list:
            station = StationInfo()
            station.ssid = ssid.encode('utf-8', 'replace')
            station.ssid_suffix = suffix.encode('utf-8', 'replace')
            randomize_station(station)
            station_info.append(station)
    return station_info


def randomize_station(station_info):
    station_info.sequence  = random.randint(0, 0xfff)
    station_info.bssid = bytes([
        random.randint(0, 0x7f) << 1,
        random.randint(0, 0xff),
        random.randint(0, 0xff),
        random.randint(0, 0xff),
        random.randint(0, 0xff),
        random.randint(0, 0xff)])
    sub_channel = random.choice((1, 3))
    if sub_channel == 1:
        next_channel = random.randint(1, 9)
    else:
        next_channel = random.randint(5, 13)
    station_info.channel = next_channel
    station_info.sub_channel = sub_channel
    print('Channel {:2d} {}, BSSID {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, ESSID: {!r}\t+ {!r}'.format(
        next_channel,
        (None, 'Ce', None, 'eC')[sub_channel],
        station_info.bssid[0],
        station_info.bssid[1],
        station_info.bssid[2],
        station_info.bssid[3],
        station_info.bssid[4],
        station_info.bssid[5],
        station_info.ssid.decode('utf-8', 'replace'),
        station_info.ssid_suffix.decode('utf-8', 'replace')))


def hop_channel(dev):
    next_channel = random.randint(1, 11)
    subprocess.call(['iw', 'dev', dev, 'set', 'channel', str(next_channel)])
    print('Hop to channel {:2d} for beacon'.format(next_channel))


def main(dev):
    scapy_L2socket = scapy.conf.L2socket(iface=dev)
    try:
        station_info = initialize_stations(ssid_list, ssid_suffixes, SSID_DUPLICATES)
        loop_interval = (BEACON_INTERVAL * 0.001024) / len(station_info)
        now = time.monotonic()
        packet_sent = 0
        last_stat = now
        last_hop, next_hop = now, 7.5
        last_rand, next_rand = now, 10
        last_loop = now
        while True:
            now = time.monotonic()
            if now - last_stat >= 5:
                last_stat = now
                print('{} packet sent'.format(packet_sent))
                packet_sent = 0
            if now - last_hop >= next_hop:
                last_hop = now
                next_hop = random.random() * 5 + 5
                hop_channel(dev)
            if now - last_rand >= next_rand:
                last_rand = now
                next_rand = random.random() * 10 + 10
                randomize_station(random.choice(station_info))
            packet = create_beacon_packet(random.choice(station_info))
            packet = scapy.RadioTap(b'\x00\x00\x08\x00\x00\x00\x00\x00' + packet)
            scapy_L2socket.send(packet)
            packet_sent += 1
            now = time.monotonic()
            if now - last_loop < loop_interval:
                last_loop += loop_interval
                time.sleep(last_loop - now)
            else:
                last_loop = now
    finally:
        scapy_L2socket.close()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: {} <devname>'.format(sys.argv[0]))
        print()
        sys.exit(1)
    main(sys.argv[1])
