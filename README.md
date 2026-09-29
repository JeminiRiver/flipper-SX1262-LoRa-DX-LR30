# Flipper Zero + DX-LR30 (SX1262) LoRa Relay

Fork of [ElectronicCats/flipper-SX1262-LoRa](https://github.com/ElectronicCats/flipper-SX1262-LoRa), retargeted to drive a bare **DX-LR30** (Semtech SX1262) LoRa module on a Flipper Zero perfboard.

> [!WARNING]
> **Hardware support is replaced, not extended.** This fork drives the DX-LR30's external `RXEN`/`TXEN` antenna-switch pins and does **not** support the upstream Electronic Cats Sub-GHz add-on board. A Flipper with that add-on board will not transmit or receive correctly with this build: the antenna-switch wiring, pin map, and TX power have been changed outright. There is no build-time or menu option to switch between the two boards.

> [!CAUTION]
> The changes have been largely AI coded using `DeepSeek-V4-Pro`. I worked with the [documentation](https://github.com/DX-SMART/LoRaModule) from the [hardware manufacturer](https://en.szdx-smart.com/EN/zwfa/SX1262/190.html) and have put eyes on every changed / added line of code made to the original project as well as tested all the changes quite extensively with my own hardware. All that being said, it's still AI generated code and I have not reviewed the entirety of the original project either, Use with caution.

## What this fork changes

| Area | Upstream | This fork |
|---|---|---|
| Supported hardware | Electronic Cats Sub-GHz add-on board | Bare DX-LR30 on perfboard (add-on board **not** supported) |
| Antenna switch | SX1262 `DIO2` controls the RF switch | External `RXEN`/`TXEN` pins driven by the Flipper (`SetDio2AsRfSwitchCtrl` removed) |
| TX power | +22 dBm | +14 dBm (safe on the Flipper's 3.3 V rail) |
| Keyboard icons | Firmware `text_input.c` with old icon names | Renamed to Momentum SDK names (`I_KeySaveSelected_22x11`, `I_KeyBackspace_17x11`, etc.) |
| Radio defaults | Generic 915 MHz defaults | Meshtastic LongFast baked in: 906.875 MHz, 250 kHz, SF11, CR 4/5, sync word 0x2B |
| USB output | None (SD-card log only) | Single-CDC serial frames (`@S…@E`) for the companion TUI |
| App identity | appid `lora_app` | appid `lora_sx1262_dxlr30`, "LoRa DX-LR30 Relay" |

## Hardware

### Wiring (module → Flipper Zero header)

Flipper pin numbers are the official numbering (1 = 5V, 18 = GND). Wire by the MCU GPIO name to be safe; community diagrams sometimes number differently.

| DX-LR30 | Flipper pin | GPIO | Notes |
|---|---|---|---|
| VCC | 9 (3.3 V) | — | 3.3 V only, never 5 V |
| GND | 8 or 18 | — | Common ground |
| NSS | 16 | PC0 | Active-low chip select |
| NRST | 15 | PC1 | Active-low reset |
| MOSI | 2 | PA7 | External SPI MOSI |
| SCK | 5 | PB3 | External SPI SCK |
| MISO | 3 | PA6 | External SPI MISO |
| DIO1 | 7 | PC3 | Packet-ready interrupt (polled) |
| BUSY | 14 | PB7 | Active-high busy |
| DIO2 | — | — | Leave unconnected |
| RXEN | 6 | PB2 | Active-high receive enable (added) |
| TXEN | 4 | PA4 | Active-high transmit enable (added) |

### Requirements

- Must be the **LR30** (SX1262). The LR20 in the same kit family is an LLCC68 — different chip, will not work.
- The 850–930 MHz variant (`DX-LR30-900-*`) covers the US915/EU868 menus. The 433 MHz variant will not reach 915 MHz.
- **Never key the radio without an antenna** — this damages the PA.
- At 14 dBm the module draws ~45 mA on TX, within the Flipper's 3.3 V budget. Raising power back toward 22 dBm requires a separate 3.3 V supply with shared ground.

## Firmware changes vs upstream

`applications_user/lora_app/lora.c`:

- `pin_txen = &gpio_ext_pa4` and `pin_rxen = &gpio_ext_pb2` replace the unused `pin_nss0`.
- `begin()` initializes TXEN/RXEN as push-pull outputs, both low at idle.
- `setModeReceive()` drives RXEN high / TXEN low before `SetRx`.
- `transmit()` drives RXEN low / TXEN high before `SetTx`, then returns the antenna to RX after TX completes.
- Removed the `SetDio2AsRfSwitchCtrl` (0x9D) block from `configureRadioEssentials()`.
- `SetTxParams` power byte set to `14`.
- `setModeStandby()` is now called before every config command (`SetRfFrequency`, `SetModulationParameters`, sync-word register write, `SetPacketParameters`). The SX1262 only accepts these in standby; the upstream code issued them from the wrong mode and the radio could stay on its boot defaults.
- `configureRadioEssentials()` now boots directly into Meshtastic LongFast: `configSetFrequency(906875000)` (US slot 20), `configSetPreset(PRESET_DEFAULT)` → 250 kHz / SF11 / CR 4/5, and `configSetSyncWord(0x2B, 0x44)`.

`applications_user/lora_app/lora_relay.c`:

- `serial_open_port()` / `serial_close_port()` select the **single-CDC** USB config (`usb_cdc_single`, port 0). No dual-CDC.
- The sniffer emits one binary frame per received packet over CDC: `@S` | length (2 bytes big-endian) | payload (N bytes) | RSSI (2 bytes big-endian signed) | SNR (1 byte signed) | `@E` | `\r\n`. The companion TUI parses these markers.
- Frames share the CLI's CDC device; keep qFlipper/Flipper Lab closed while sniffing.

`applications_user/lora_app/application.fam`:

- appid renamed to `lora_sx1262_dxlr30`; name "LoRa DX-LR30 Relay"; category `SubGhz`; description notes the USB serial companion TUI.

`applications_user/lora_app/modules/text_input.c`:

- Keyboard icon references updated to Momentum's SDK names.

## Companion dashboard (read-only Meshtastic sniffer)

`meshtasticDashboard.py` (repo root) is a Python [Textual](https://textual.textualize.io/) TUI that reads the Flipper's CDC stream and presents a read-only Meshtastic view. It **sniffs and decrypts only — it never transmits**, and it has no path back to the radio.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 meshtasticDashboard.py            # interactive device menu (VID/PID labeled)
```

Features:

- Tabs: Nodes, Node Detail, Channels, Channel Messages, Messages.
- Per-channel grouping by the 3-byte channel hash; in-TUI **Add channel** flow to map a hash to a name + base64 PSK (stored in `reports/keys.json`).
- Node registry (`reports/nodes.json`) with name, hardware, role, position (with staleness), battery, and per-node packet/last-seen counts.
- Decrypts channel text and metadata; DM/ack *content* is intentionally left unreadable (Meshtastic DM keys are not derivable from on-air data).
- Message log (`reports/messages.jsonl`) and per-channel stats (`reports/channel_stats.json`).

All state is written to a `reports/` directory next to the script (created on launch).

### Channel names and keys

Only the 3-byte channel hash is transmitted on air. Channel **names and PSKs are secrets** — they never appear on air and cannot be recovered by sniffing. They must be supplied by the user (the in-TUI Add-channel flow writes them to `reports/keys.json`). The default LongFast PSK (`1PG7OiApB1nwvP+rz05pAQ==`) is tried for any channel with no registered key.

## Build (Momentum firmware)

Targets the same firmware the Flipper is running (Momentum, SDK 87.x). A `.fap` built against a different SDK/firmware will refuse to launch with an API-version mismatch.

```bash
# one-time: install and point uFBT at Momentum's SDK
pipx install ufbt
ufbt update --index-url=https://up.momentum-fw.dev/firmware/directory.json --channel=release

# build
cd applications_user/lora_app
ufbt            # produces dist/lora_app.fap
```

Install: `ufbt launch` (Flipper connected over USB, qFlipper/Flipper Lab closed), or copy `dist/lora_app.fap` to the SD card's `apps/` folder.

## Verify

- A successful boot to the app menu means `begin()` passed: SPI, NSS, BUSY and NRST are all wired correctly (the sanity check reads register value `0x14` from the SX1262).
- The sniffer screen shows `RSSI: 0` until a packet is received — this is the idle state, not an error.
- On the sniffer screen, RXEN (pin 6 / PB2) should measure ~3.3 V and TXEN (pin 4 / PA4) ~0 V. This confirms the antenna is switched to the receive path.
- To prove TX/RX end to end, transmit from a second LoRa node (another module, Meshtastic radio, etc.) on 915 MHz with **matching** bandwidth, spreading factor, coding rate and sync word. A parameter mismatch — especially sync word — means packets are silently ignored.

---

# Original README (ElectronicCats flipper-SX1262-LoRa)

![GitHub release (with filter)](https://img.shields.io/github/v/release/ElectronicCats/flipper-SX1262-LoRa?color=%23008000)
![GitHub actions](https://img.shields.io/github/actions/workflow/status/ElectronicCats/flipper-SX1262-LoRa/build.yml)

# Flipper LoRa Relay App :dolphin:

Work with LoRa radio communication signals. Now you can interact with LoRa transmissions using the Flipper Zero. Basic tasks such as sniffing and injection are available, making it easy to perform activities such as analysis, error detection and configuration of new peripherals to the network.

<p align="center">
 <img src="https://github.com/ElectronicCats/flipper-SX1262-LoRa/blob/main/assets/start_sniff.png" alt="Sniffing Screen" height=200 />
 <img src="https://github.com/ElectronicCats/flipper-SX1262-LoRa/blob/main/assets/lora_tx.png" alt="Send Screen" height=200 />
</p>

<p align=center>
 <a href="https://github.com/ElectronicCats/flipper-SX1262-LoRa/wiki">
  <img src="https://github.com/ElectronicCats/flipper-SX1262-LoRa/blob/main/assets/ec_wki_button.png" alt="Wiki redirection button" width=200 />
 </a>
</p>

Requires the [**Electronic Cats Flipper Add-On: Sub-GHz**](https://electroniccats.com/store/flipper-add-on-subghz/).

## Features

* Customize the LoRa parameters.
* Menu for LoRaWAN US915 and EU868
* Read and display data sniffed from LoRa devices.
   <!-- * Hexadecimal or Normal data output format selector -->
* Export sniffing sessions in LOG files to the SD card.
* Send LoRa packets from the LOG file.
  <!-- * Saves the recent packet structures, then allows you to modify & inject them again -->

## How to contribute <img src="https://electroniccats.com/wp-content/uploads/2018/01/fav.png" alt="Electronic Cats Logo" height="35"/><img src="https://raw.githubusercontent.com/gist/ManulMax/2d20af60d709805c55fd784ca7cba4b9/raw/bcfeac7604f674ace63623106eb8bb8471d844a6/github.gif" alt="GitHub Logo" height="30"/>

Contributions are welcome!

Please read the document [**Contribution Manual**](https://github.com/ElectronicCats/electroniccats-cla/blob/main/electroniccats-contribution-manual.md)  which will show you how to contribute your changes to the project.

✨ Thanks to all our [**contributors**](https://github.com/ElectronicCats/flipper-SX1262-LoRa/graphs/contributors)! ✨

See [**_Electronic Cats CLA_**](https://github.com/ElectronicCats/electroniccats-cla/blob/main/electroniccats-cla.md) for more information.

See the  [**community code of conduct**](https://github.com/ElectronicCats/electroniccats-cla/blob/main/electroniccats-community-code-of-conduct.md) for a vision of the community we want to build and what we expect from it.

## Maintainer

<p align="center">
 <a href="https://github.com/sponsors/ElectronicCats">
  <img src="https://electroniccats.com/wp-content/uploads/2020/07/Badge_GHS.png" alt="Sponsor button" height="104" />
 </a>
</p>

Electronic Cats invests time and resources in providing this open-source design, please support Electronic Cats and open-source hardware by purchasing products from Electronic Cats!
