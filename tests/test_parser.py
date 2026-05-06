from scanner.parser import parse_iw_scan, parse_iwlist_scan, parse_nmcli_scan


def test_nmcli_terse_parser_handles_escaped_bssid_and_markup_ssid():
    raw = r"*:AA\:BB\:CC\:11\:22\:33:Lab[ssid]:Infra:6:2437 MHz:130:78:bars:WPA2"

    networks = parse_nmcli_scan(raw)

    assert len(networks) == 1
    assert networks[0]["bssid"] == "AA:BB:CC:11:22:33"
    assert networks[0]["ssid"] == "Lab[ssid]"
    assert networks[0]["channel"] == 6
    assert networks[0]["frequency"] == 2.437
    assert networks[0]["signal"] == -61
    assert networks[0]["encryption"] == "WPA2"


def test_iw_parser_handles_hidden_network_and_channel_14():
    raw = """
BSS AA:BB:CC:11:22:33(on wlan0)
        freq: 2484
        signal: -42.00 dBm
        SSID:
        capability: ESS Privacy ShortSlotTime (0x0411)
        RSN:     * Version: 1
"""

    networks = parse_iw_scan(raw)

    assert len(networks) == 1
    assert networks[0]["hidden"] is True
    assert networks[0]["ssid"] == "<hidden>"
    assert networks[0]["channel"] == 14
    assert networks[0]["encryption"] == "WPA2"


def test_iwlist_parser_detects_wps_and_wpa2():
    raw = """
wlan0     Scan completed :
          Cell 01 - Address: AA:BB:CC:11:22:44
                    Channel:6
                    Frequency:2.437 GHz (Channel 6)
                    Quality=70/70  Signal level=-40 dBm
                    Encryption key:on
                    ESSID:"Office"
                    IE: IEEE 802.11i/WPA2 Version 1
                    IE: Wi-Fi Protected Setup
"""

    networks = parse_iwlist_scan(raw)

    assert len(networks) == 1
    assert networks[0]["bssid"] == "AA:BB:CC:11:22:44"
    assert networks[0]["ssid"] == "Office"
    assert networks[0]["wps"] is True
    assert networks[0]["encryption"] == "WPA2"
