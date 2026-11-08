# WiFi Honeypot

Dedicated lab AP with DHCP event logging.

## Setup

Python 3.10+ on a Linux desktop.
From this folder:

```sh
sudo apt install python3-tk hostapd dnsmasq iproute2 iw
python3 honeypot_gui.py
```

`./run.sh` works from any directory and uses `.venv/bin/python` when present,
otherwise `python3` from your current environment. Install OS dependencies
separately. No launcher installs packages automatically.

## Desktop launcher

```sh
python3 install-launcher.py --desktop
```

Run the installer as your normal desktop user. It adds the app to your application
menu and desktop with its bundled icon. Omit `--desktop` for a menu entry only.
Keep the checkout in place; rerun the installer after moving it. On desktops that
ask, choose **Allow Launching** or **Mark as Trusted** for the desktop shortcut.

The icon requests administrator authentication through PolicyKit (`pkexec`).
Install your distribution's PolicyKit package and use an X11 desktop session.
For a standard user icon instead, add `--normal-user` when installing.
For administrator launch from a graphical terminal, use `./run-admin.sh`.
This preserves X11 display authentication and uses this project's virtual
environment. Elevated sessions store home-directory settings and exports as root;
desktop notifications may be unavailable. Native Wayland elevation is unsupported.

## Checks

```sh
python3 -m compileall -q -x '/\.venv/' .
# For GUI tests, install xvfb and xauth, then run:
xvfb-run -a python3 -m unittest discover -s tests -v
bash -n *.sh
```

The GitHub Actions workflow runs these offline checks on Python 3.10, 3.12 and
3.13 and 3.14. It checks GUI construction under a virtual X11 display, without live network
operations or administrator authentication. Hardware behavior needs local testing.

## Repository use

This folder is self-contained: copy it into its own GitHub repository with its
hidden `.github/` and `.gitignore` files. No sibling projects are required.
Generated data, credentials, captures and virtual environments are ignored.
No license has been selected; add your chosen LICENSE before distributing under
an open-source license.

## AP configuration


Use a dedicated adapter that supports AP mode. The app creates `honeypot.db`
on first launch and appends DHCP events there. This is an open lab AP with DHCP logging, with
no captive portal, DNS service, routing, or Internet sharing.

1. Install `hostapd dnsmasq python3-tk` using your OS package manager.
2. Identify the dedicated adapter with `iw dev`. Disconnect it from existing
   networks and, if NetworkManager manages it, run
   `sudo nmcli device set YOUR_INTERFACE managed no`.
3. Copy `hostapd.conf.example` to `hostapd.conf` and `dnsmasq.conf.example` to
   `dnsmasq.conf` here. Set the same interface in both files; set the local country
   in hostapd. Use an unused subnet. Stop any separately configured service using
   this adapter or its DHCP port before starting.
4. From this project folder, launch from a graphical terminal:
   `./run-admin.sh`.
   Export `HONEYPOT_INTERFACE=YOUR_INTERFACE` before running this command.
5. Click Start. Stop/close terminates only processes started by this app and
   removes only the address it added. The adapter remains up.
6. Restore management afterwards if changed:
   `sudo nmcli device set YOUR_INTERFACE managed yes`.

Optional environment settings: `HONEYPOT_IP` (default `192.168.50.1/24`),
`HONEYPOT_HOSTAPD_CONF`, `HONEYPOT_DNSMASQ_CONF`. Config paths default to this
folder, independent of your current directory. Match the DHCP subnet to the IP.


## Troubleshooting

- Missing Python module: install `requirements.txt` into `.venv` if provided.
- Missing `tkinter`: install the Python Tk package from your OS package manager.
- A command is unavailable: install the corresponding OS package listed above.
- Icons stopped working after moving the checkout: rerun `install-launcher.py`.
