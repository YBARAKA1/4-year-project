# Network IDS

A desktop network intrusion detection console. It watches traffic on the host, shows system load and live packet rates, and flags a small set of common attack patterns. The interface is a Tkinter application with a dark sensor theme.

This is a host sensor, not a full network IDS appliance. It sees packets on the machine where it is running. It does not replace a firewall, and it does not invent traffic when capture is unavailable.

## What it does

After a short boot screen, the console opens with every page available. There is no sign-in step.

| Page | What you get |
| --- | --- |
| Dashboard | CPU and memory gauges, inbound and outbound rate, and a 60-second traffic chart. Click a gauge to list processes. |
| Packet Stream | A live table of captured packets. Filter by protocol and open a packet for details. |
| Traffic Analysis | Volume trends, protocol mix, top talkers, geolocation, and packet inspection. Results can be exported. |
| Threat Alerts | Real-time alerts from the local detectors, plus Suricata events if an `eve.json` log is present. You can mark an IP blocked or safe. |
| Port Scanner | Scan a target for open ports from inside the console. |
| Terminal | A command box inside the app. Commands run on this host. |

The sensor dot in the top bar is accurate:

- **sensor live** means a capture socket is open and packets are arriving.
- **sensor idle — capture needs root** means the process cannot open a raw socket. Gauges still update. Traffic stays blank instead of showing fake rates.

## How detection works

The live detector looks at packets as they arrive. Counts reset about once a second.

- **SYN flood:** more than 50 TCP SYN packets from the same source in that window.
- **UDP flood:** more than 200 UDP packets from the same source in that window.
- **ARP spoof:** more than one MAC address claimed for the same IP.
- **Wi-Fi deauthentication:** an 802.11 deauthentication frame, if the interface is capturing wireless frames.

These are simple thresholds. A busy LAN can trip them without being an attack. Treat the alerts as signals to inspect, not as proof.

Threat Alerts can also read Suricata JSON. It looks first at `/var/log/suricata/eve.json`, then at `eve.json` in this project folder. If neither file exists, that view simply starts empty.

## Geolocation

Public addresses are looked up in `GeoLite2-City.mmdb`. Each public address is queried once.

Private and special addresses are not in that database. They are labeled instead of treated as errors:

- `192.168.0.0/16`, `10.0.0.0/8`, and `172.16.0.0/12` → **Local network**
- `127.0.0.0/8` → **Loopback**
- link-local addresses → **Link-local**

City and country names from GeoLite are approximate. They are not a street address. See `README.txt` for the MaxMind notice.

## Requirements

- Linux with a graphical session. The app is a window, so `DISPLAY` must be set.
- Python 3.13 and the project virtual environment in `newids/`
- System package `python3-tk` (Tk is not installed by pip)
- PostgreSQL reachable at the host and port in `.env` (this machine uses the `integral-postgres` container on `localhost:5432`)
- Database `ids_db` with the tables the app writes to
- For live capture: permission to open a raw packet socket, normally root

Main Python libraries already present in `newids/` include Scapy, psutil, matplotlib, pandas, psycopg2, geoip2, and python-dotenv.

## How to launch

Open a terminal in the project folder.

```bash
cd /home/kali/Documents/4-year-project
```

The virtual environment must be the one in this folder. `python` on the system does not have the project packages.

```bash
newids/bin/python dashboard.py
```

You should see a short boot log, then the NIDS window. The boot text reports the hostname, whether capture is available, and which detectors are loaded.

Do not start the app with `python dashboard.py` unless `newids` is active and `which python` points at `newids/bin/python`. An old path in the environment will silently use the system interpreter.

### Live packet capture

Without extra privileges the window still opens. CPU and memory are real. Packet tables, traffic charts, and detection stay empty, and the status line says capture needs root.

To capture on the local interfaces:

```bash
cd /home/kali/Documents/4-year-project
sudo -E newids/bin/python dashboard.py
```

`-E` keeps your environment, including `DISPLAY`, so the window can open from a desktop session. Enter your password when sudo asks. After the first packets arrive, the status changes to **sensor live**.

Stop the app by closing the window. If a capture run is stuck in the terminal, press `Ctrl+C` there.

## Database

Connection settings are read from `.env` in the project folder:

- `DB_NAME` — database name (`ids_db`)
- `DB_USER` — database user
- `DB_PASSWORD` — password for that user
- `DB_HOST` — usually `localhost`
- `DB_PORT` — usually `5432`

Do not commit real passwords. The copy of `.env` on this machine is local configuration.

The app expects these tables in `ids_db`:

- `users`, `pending`, `rejected` — leftover account tables; the console no longer asks you to sign in
- `low_threats`, `medium_threats`, `high_threats` — stored alerts by severity
- `threat_actions` — block and mark-safe actions
- `top_talkers` — source, destination, and volume
- `geolocation` — stored location labels

If PostgreSQL is the Docker container `integral-postgres`, it must be running before you open Traffic Analysis or Threat Alerts. Those pages write to the database when capture is active. A stopped database does not stop the window from opening, but saves and lookups will fail in the terminal.

Check that the container is up:

```bash
docker ps --filter name=integral-postgres
```

## Configuration files

| File | Role |
| --- | --- |
| `dashboard.py` | Entry point. Boot screen, sidebar, dashboard, packet stream, and the live detector. |
| `trafficanalysis.py` | Traffic charts, talkers, geolocation, and inspection. |
| `threatalert.py` | Alert list, Suricata import, and block / mark-safe. |
| `port_scanner.py` | Port scan page. |
| `terminal.py` | In-app command terminal. |
| `.env` | Database and mail settings. Mail is unused now that sign-in is removed. |
| `GeoLite2-City.mmdb` | City database for public IP labels. Must sit next to the scripts. |
| `eve.json` | Optional sample Suricata log used if the system Suricata log is absent. |

## What you should see

1. A boot window titled **NIDS** types a few status lines, then closes.
2. The main window opens maximized, titled **NIDS — host sensor**.
3. The left bar lists Dashboard, Packet Stream, Traffic Analysis, Threat Alerts, Port Scanner, and Terminal.
4. The dashboard shows CPU and memory as measured percentages. The arc length matches the value.
5. Inbound and outbound rates update about once a second when capture is live. Units are KB/s over the last sample window. If capture is idle, those lines show **no capture socket**.

## Troubleshooting

**`No module named tkinter`**

Install the system Tk binding, then start the app again with `newids/bin/python`:

```bash
sudo apt install python3-tk
```

**`No module named ...` for another library**

You are not using the project virtual environment. Launch with `newids/bin/python dashboard.py`.

**`expected integer but got "Sans"`**

A font name with a space was passed to Tk without braces. The app uses the helpers in `constants.py` to avoid that. Do not set widget fonts to `("DejaVu Sans", 10)`.

**Sensor stays idle and traffic is blank**

The process cannot open a raw socket. Restart with `sudo -E newids/bin/python dashboard.py`. A normal user session will not see packets.

**GeoIP messages about 192.168.x.x**

Those addresses are on your LAN. They are labeled **Local network** and are not looked up in GeoLite. Only public addresses are queried.

**PostgreSQL authentication failed**

The password in `.env` does not match the running server. This project talks to Postgres on `localhost:5432`. Point `DB_PASSWORD` at that server’s password, and make sure `ids_db` exists.

**Threat Alerts is empty**

Either no detector threshold has been crossed, or there is no Suricata `eve.json`. An empty list is normal on a quiet network.

**The in-app terminal**

It runs commands as the same user that started the app. A root launch can run privileged commands. Do not paste untrusted input into it.
