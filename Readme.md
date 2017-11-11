wifijam -- An 802.11n beacon frame transmission program
=======================================================

Wifijam is a program that sends 802.11n beacon frames to announce fake Wi-Fi access points. These fake access points will have passwords and can not be really connected to.

This program comes with two versions: a Scapy version and an ESP8266 version.

The Scapy version requires a Linux computer with a Wi-Fi card supporting the "monitor" mode, as well as Python 3, [scapy-python3](https://pypi.python.org/pypi/scapy-python3), and [aircrack-ng](https://www.aircrack-ng.org/).

The ESP8266 version requires a development board with an ESP8266 Wi-Fi chip (usually less than $9), along with the Arduino IDE with [ESP8266 plugins](https://arduino-esp8266.readthedocs.io/en/latest/installing.html).

Usage
-----

Edit the source code, modify `ssid_list` for a list of SSIDs you wish to send, modify `SSID_DUPLICATES` for the number of duplicates for each SSID.

For the Scapy version, type:

    airmon-ng start wls0
    ./wifijam.py wls0mon

… where `wls0` is the device name of your Wi-Fi card, `wls0mon` is the monitor name given by `airmon-ng`.

After you finished, type:

    airmon-ng stop wls0mon

For the ESP8266 version, connect your development board to the Arduino IDE, click Sketch → Upload. You might need to press the "Flash" button if your development board has one.

Warning
-------

The program's authors release this program in the hope that it will be useful, and can not control how the users are modifying it or using it. Therefore the program's authors will not be responsible for the users' behavior.

Please do not use this program to interfere with others' communication, or to spread harmful information or steal others' data, or to do anything prohibited by the law or the government.

License
-------

This program is released under GNU General Public License version 3, see [COPYING](COPYING) for details.
