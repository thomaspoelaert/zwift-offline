# Zwift Video Monitor

Diagnostic tool that monitors a Zwift ride on Windows (meant for Zwift Video /
Zwift Plus routes) and collects what is needed to find out whether the video
content can be cached or served offline, and how.

It is **read-only**: it does not change Zwift, DNS, hosts file or network settings.

## What it records

| Source | What you learn |
|---|---|
| `pktmon` packet capture (first 700 bytes of each packet) | DNS names, TLS SNI hostnames, plain HTTP URLs, volume per host, QUIC/HTTP3 use |
| Zwift process connections (polled every 2 s) | which Zwift process talks to which host/port |
| Zwift process disk I/O and open files | whether the video is written to disk |
| Before/after snapshot of the Zwift folders | which files appeared or grew during the ride |
| Windows DNS client cache, hosts file, DNS/DoH/proxy settings | how names were resolved |
| Copies of `Documents\Zwift\Logs\*.txt`, `prefs.xml`, `Zwift_ver_cur.xml` | Zwift's own log, which lists many URLs |

Output goes to `Desktop\ZwiftVideoMonitor_<timestamp>\` with a `REPORT.txt`
summary, CSV/JSON detail files and the `.pcapng`, plus a `.zip` of the whole folder.

## Usage

1. Download `zwift_video_monitor.exe` from the GitHub Actions artifact
   (workflow *video-monitor*).
2. Right-click it and choose **Run as administrator** (needed for `pktmon`).
3. Press Enter to start, log in to Zwift, choose a **Zwift Video** route and
   ride 5 to 10 minutes. If Zwift has a video quality setting, open it once.
4. Press Enter in the tool window to stop. Wait for the analysis.
5. Send the `.zip` on the Desktop.

Options:

```
zwift_video_monitor.exe --duration 600     stop automatically after 600 s
zwift_video_monitor.exe --no-pcap          do not include the .pcapng in the zip
zwift_video_monitor.exe --pkt-size 0       capture full packets (large files!)
zwift_video_monitor.exe --parse X.pcapng   re-analyse an existing capture
```

Privacy: TLS payloads are encrypted, so the capture contains hostnames and
volumes, not content. The Zwift log files contain your player id and route
names. Review the folder before sharing if that matters.

## Building the exe

The workflow `.github/workflows/video-monitor.yaml` builds it on a Windows runner
with PyInstaller (`--onefile --uac-admin`) and uploads it as an artifact. Locally:

```
pip install pyinstaller psutil
pyinstaller --onefile --console --uac-admin --name zwift_video_monitor tools/zwift_video_monitor/zwift_video_monitor.py
```

Run `python tools/zwift_video_monitor/selftest.py` to test the capture parser.
