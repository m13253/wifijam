/*
  wifijam -- An 802.11n beacon frame transmission program
  Copyright (C) 2017  Star Brilliant <m13253@hotmail.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ESP8266WiFi.h>
#ifdef ESP8266
extern "C" {
#include <user_interface.h>
}
#endif

#define BEACON_INTERVAL 100
static const char *const ssid_list[] = {
  // Space - Face with tears of joy
  " \xf0\x9f\x98\x82",
};

#define SSID_DUPLICATES 9
static const char *const ssid_suffixes[] = {
  // Empty
  "",
  // Zero width space
  "\xe2\x80\x8b",
  // Zero width non-joiner
  "\xe2\x80\x8c",
  // Zero width joiner
  "\xe2\x80\x8d",
  // Word joiner
  "\xe2\x81\xa0",
  // Function application
  "\xe2\x81\xa1",
  // Invisible times
  "\xe2\x81\xa2",
  // Invisible separator
  "\xe2\x81\xa3",
  // Invisible plus
  "\xe2\x81\xa4",
};

#define BEACON_MAX_LENGTH 0x100
static const char beacon_header[0x26] = {
  // 0x00: Frame control field
  0x80, 0x00,
  // 0x02: Duration: 0 microseconds
  0x00, 0x00,
  // 0x04: Receiver address: Broadcast
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  // 0x0a: Transmitter address: Random
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  // 0x10: BSSID: Random
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  // 0x16: Sequence number (12 bits), fragment number (4 bits)
  0x00, 0x00,

  // 0x18: Timestamp
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  // 0x20: Beacon interval (times 1.024 ms)
  0x64, 0x00,
  // 0x22: Capabilities: ESS, WEP, Short Preamble, Short Slot Time
  0x31, 0x04,
  // 0x24: SSID parameter set
  0x00, 0x00,
  // 0x26
};

static const char beacon_tail[0x41] = {
  // 0x00: Supported rates: 1M, 2M, 5.5M, 11M, 6M, 9M, 12M, 18M
  0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
  // 0x0a: Current channel: Random
  0x03, 0x01, 0x00,
  // 0x0d: RSN Information: WPA2
  0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
  0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
  0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
  // 0x23: Extended supported rates: 24M, 36M, 48M, 54M
  0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
  // 0x29: HT Information
  0x3d, 0x16, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  // 0x41
};

typedef struct {
  const char *ssid;
  const char *ssid_suffix;
  uint16_t    sequence;
  char        bssid[6];
  uint8_t     channel;
  uint8_t     sub_channel;
} station_info_t;

static size_t get_string_length_with_limit(const char *s, size_t limit = 32) {
  const char *last_byte = s;
  size_t byte_len = 0;
  size_t rune_len = 0;
  while(byte_len <= limit) {
    if(*last_byte == 0x00) {
      return byte_len;
    }
    if((*last_byte & 0xc0) != 0x80) {
      rune_len = byte_len;
    }
    ++last_byte;
    ++byte_len;
  }
  return rune_len;
}

static void print_escaped_string(const char *s) {
  while(*s != 0x00) {
    if(*s >= 32 && *s <= 127) {
      Serial.print(*s);
    } else {
      Serial.printf("\\x%02x", *s);
    }
    ++s;
  }
}

static size_t create_beacon_packet(char packet[BEACON_MAX_LENGTH], station_info_t *station_info) {
  size_t ssid_len   = get_string_length_with_limit(station_info->ssid);
  size_t suffix_len = get_string_length_with_limit(station_info->ssid_suffix, 32 - ssid_len);
  memcpy(packet,        beacon_header,      0x26);
  memcpy(packet + 0x0a, station_info->bssid, 6);
  memcpy(packet + 0x10, station_info->bssid, 6);
  *(uint16_t *) (packet + 0x16) = station_info->sequence++ << 4;
  *(uint16_t *) (packet + 0x18) = random(0x10000);
  *(uint16_t *) (packet + 0x1a) = random(0x10000);
  *(uint8_t *)  (packet + 0x1c) = random(0x100);
  *(uint16_t *) (packet + 0x20) = BEACON_INTERVAL;
  *(uint8_t *)  (packet + 0x25) = (uint8_t) (ssid_len + suffix_len);
  memcpy(packet + 0x26,                         station_info->ssid,        ssid_len);
  memcpy(packet + 0x26 + ssid_len,              station_info->ssid_suffix, suffix_len);
  memcpy(packet + 0x26 + ssid_len + suffix_len, beacon_tail, 0x41);
  *(uint8_t *) (packet + 0x26 + ssid_len + suffix_len + 0x0c) = station_info->channel;
  *(uint8_t *) (packet + 0x26 + ssid_len + suffix_len + 0x2b) = station_info->channel;
  *(uint8_t *) (packet + 0x26 + ssid_len + suffix_len + 0x2c) = 0x4 | (station_info->sub_channel & 0x3);
  return 0x26 + ssid_len + suffix_len + 0x41;
}

static size_t initialize_stations(station_info_t *station_info, const char *const ssid_list[], size_t ssid_list_length, const char *const ssid_suffixes[], size_t ssid_duplicates) {
  for(size_t i = 0; i < ssid_duplicates; ++i) {
    for(size_t j = 0; j < ssid_list_length; ++j) {
      size_t station_id = i * ssid_list_length + j;
      station_info[station_id].ssid = ssid_list[j];
      station_info[station_id].ssid_suffix = ssid_suffixes[i];
      randomize_station(station_info, station_id);
    }
  }
  hop_channel();
  return ssid_duplicates * ssid_list_length;
}

static void randomize_station(station_info_t *station_info, size_t station_id) {
  station_info[station_id].sequence = random(0x1000);
  station_info[station_id].bssid[0] = random(0x80) << 1;
  station_info[station_id].bssid[1] = random(0x100);
  station_info[station_id].bssid[2] = random(0x100);
  station_info[station_id].bssid[3] = random(0x100);
  station_info[station_id].bssid[4] = random(0x100);
  station_info[station_id].bssid[5] = random(0x100);
  uint8_t next_channel, sub_channel;
  if(random(0, 2) != 0) {
    sub_channel = 1;
    next_channel = random(1, 10);
  } else {
    sub_channel = 3;
    next_channel = random(5, 14);
  }
  station_info[station_id].channel = next_channel;
  station_info[station_id].sub_channel = sub_channel;
  Serial.printf("Channel %2u %s, BSSID %02x:%02x:%02x:%02x:%02x:%02x, ESSID: \"",
    next_channel,
    sub_channel == 1 ? "Ce" : "eC",
    station_info[station_id].bssid[0],
    station_info[station_id].bssid[1],
    station_info[station_id].bssid[2],
    station_info[station_id].bssid[3],
    station_info[station_id].bssid[4],
    station_info[station_id].bssid[5]);
  print_escaped_string(station_info[station_id].ssid);
  Serial.print("\"\t+ \"");
  print_escaped_string(station_info[station_id].ssid_suffix);
  Serial.print("\"\r\n");
}

static void hop_channel() {
  uint8_t next_channel = random(1, 12);
  wifi_set_channel(next_channel);
  Serial.printf("Hop to channel %2u for beacon\r\n", next_channel);
}

static char packet_buffer[BEACON_MAX_LENGTH];
static station_info_t station_info[SSID_DUPLICATES * (sizeof ssid_list / sizeof ssid_list[0])];
static size_t num_stations;
static unsigned long loop_interval;
static unsigned long last_loop;

void setup() {
  Serial.begin(115200);
  Serial.print("\r\n");
  randomSeed(analogRead(0));
  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(1);
  num_stations = initialize_stations(station_info, ssid_list, sizeof ssid_list / sizeof ssid_list[0], ssid_suffixes, SSID_DUPLICATES);
  loop_interval = (BEACON_INTERVAL * 1024) / num_stations;
  last_loop = micros();
}

void loop() {
  static unsigned long packet_sent = 0;
  static unsigned long packet_retry = 0;
  static unsigned long count_stat = 0;
  if(++count_stat * loop_interval >= 5000000) {
    count_stat = 0;
    Serial.printf("%lu packet sent, retry rate %lux\r\n", packet_sent, (packet_retry + packet_sent / 2) / packet_sent);
    packet_sent = 0;
    packet_retry = 0;
  }
  static unsigned long count_hop = 0;
  static unsigned long next_hop = 7500000;
  if(++count_hop * loop_interval >= next_hop) {
    count_hop = 0;
    next_hop = random(5000000, 10000000);
    hop_channel();
  }
  static unsigned long count_rand = 0;
  static unsigned long next_rand = 10000000;
  if(++count_rand * loop_interval * num_stations >= next_rand) {
    count_rand = 0;
    next_rand = random(10000000, 20000000);
    randomize_station(station_info, random(num_stations));
  }
  size_t packet_len = create_beacon_packet(packet_buffer, &station_info[random(num_stations)]);
  while(wifi_send_pkt_freedom((uint8_t *) packet_buffer, packet_len, false) != 0) {
    ++packet_retry;
    yield();
  }
  ++packet_sent;
  unsigned long now = micros();
  if((unsigned long) (now - last_loop) < loop_interval) {
    last_loop += loop_interval;
    delayMicroseconds(last_loop - now);
  } else {
    last_loop = now;
  }
}
