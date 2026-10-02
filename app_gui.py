#!/usr/bin/env python3
"""Single GUI for site blocker, firewall modes, and host-only VPN server."""

from __future__ import annotations

import io
import os
import sys
import traceback
import tkinter as tk
from contextlib import redirect_stdout, redirect_stderr
from tkinter import messagebox, scrolledtext, ttk

BASE = os.path.dirname(os.path.abspath(__file__))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

import app_proxy
import apps
import blocker
import connections
import guard
import netlock
import network_boot
import persist
import vpn_server
import wintun_tun


def capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    try:
        with redirect_stdout(buf), redirect_stderr(buf):
            result = fn(*args, **kwargs)
    except Exception:
        buf.write(traceback.format_exc())
        return buf.getvalue()
    text = buf.getvalue()
    if result is not None and not text.strip():
        text = str(result)
    return text
class ScrollableFrame(ttk.Frame):
    """A reusable vertical scrolling frame that keeps extensive inner content safely scaled within limited views."""
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas, padding=10)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        self.scrollable_frame.bind("<Enter>", self._bind_mousewheel)
        self.scrollable_frame.bind("<Leave>", self._unbind_mousewheel)

    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def _bind_mousewheel(self, event):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_mousewheel(self, event):
        self.canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
class NetLockApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("NetLock Control")
        self.geometry("800x720")
        self.minsize(700, 580)

        self.admin = blocker.is_admin()
        
        # Header area configuration
        header = ttk.Frame(self, padding=10)
        header.pack(fill="x", side="top")
        ttk.Label(header, text="NetLock", font=("Segoe UI", 16, "bold")).pack(side="left")
        status = "Administrator" if self.admin else "Not elevated — most actions will fail"
        ttk.Label(header, text=status).pack(side="right")
        self.link_label = ttk.Label(header, text="OUTSIDE: DEAD", font=("Segoe UI", 11, "bold"))
        self.link_label.pack(side="right", padx=16)
        self.after(1000, self._poll_link)

        # Main dynamic window layout splitting via unified PanedWindows
        main_pane = ttk.PanedWindow(self, orient="vertical")
        main_pane.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Top pane region containing the core multi-tab interface notebook
        nb_frame = ttk.Frame(main_pane)
        nb = ttk.Notebook(nb_frame)
        nb.pack(fill="both", expand=True)

        self.tab_sites_scroll = ScrollableFrame(nb)
        self.tab_fw_scroll = ScrollableFrame(nb)
        self.tab_vpn_scroll = ScrollableFrame(nb)
        self.tab_conn_scroll = ScrollableFrame(nb)

        self.tab_sites = self.tab_sites_scroll.scrollable_frame
        self.tab_fw = self.tab_fw_scroll.scrollable_frame
        self.tab_vpn = self.tab_vpn_scroll.scrollable_frame
        self.tab_conn = self.tab_conn_scroll.scrollable_frame

        nb.add(self.tab_sites_scroll, text="Site filter")
        nb.add(self.tab_fw_scroll, text="Firewall")
        nb.add(self.tab_vpn_scroll, text="VPN server")
        nb.add(self.tab_conn_scroll, text="All connections")
        self.nb = nb
        
        main_pane.add(nb_frame, weight=3)

        # Bottom pane region containing horizontally balanced text output boxes
        bottom_pane = ttk.PanedWindow(main_pane, orient="horizontal")
        
        stream_frame = ttk.LabelFrame(bottom_pane, text="Data stream", padding=6)
        self.stream_status = ttk.Label(stream_frame, text="Upload 0 bps   Download 0 bps", font=("Segoe UI", 10, "bold"))
        self.stream_status.pack(anchor="w", fill="x")
        self.stream = scrolledtext.ScrolledText(stream_frame, height=5, wrap="none")
        self.stream.pack(fill="both", expand=True)
        self.after(800, self._poll_stream)

        log_frame = ttk.LabelFrame(bottom_pane, text="Log", padding=6)
        self.log = scrolledtext.ScrolledText(log_frame, height=5, wrap="word")
        self.log.pack(fill="both", expand=True)

        bottom_pane.add(stream_frame, weight=1)
        bottom_pane.add(log_frame, weight=1)
        main_pane.add(bottom_pane, weight=1)

        self._build_sites()
        self._build_firewall()
        self._build_vpn()
        self._build_connections()
        nb.bind("<<NotebookTabChanged>>", self._on_tab)

        if not self.admin:
            self._log("Start with start.bat so Windows can elevate this GUI.")

        self._refresh_all()
        self.after(200, self._boot_shield)

    def _log(self, text: str) -> None:
        self.log.insert("end", text.rstrip() + "\n")
        self.log.see("end")

    def _run(self, title: str, fn, *args, **kwargs) -> None:
        self._log(f"--- {title} ---")
        out = capture(fn, *args, **kwargs)
        if out.strip():
            self._log(out)
        self._refresh_all()
    def _build_sites(self) -> None:
        ttk.Label(
            self.tab_sites,
            text="Protected sites use the AES HTTP/HTTPS tunnel when you connect. Blocked sites and blacklisted IPs are denied and can be killed by the guard.",
            wraplength=650,
        ).pack(anchor="w", fill="x")

        addrow = ttk.Frame(self.tab_sites)
        addrow.pack(fill="x", pady=6)
        ttk.Label(addrow, text="Add site").pack(side="left")
        self.new_site = tk.StringVar()
        ttk.Entry(addrow, textvariable=self.new_site, width=28).pack(side="left", padx=6)
        ttk.Button(addrow, text="Add to protection list", command=self._add_site).pack(side="left")

        btnrow = ttk.Frame(self.tab_sites)
        btnrow.pack(fill="x", pady=4)
        ttk.Button(btnrow, text="Block", command=self._block_selected_site).pack(side="left", padx=(0, 6))
        ttk.Button(btnrow, text="Unblock", command=self._unblock_selected_site).pack(side="left")

        tree_frame = ttk.Frame(self.tab_sites)
        tree_frame.pack(fill="both", expand=True, pady=(4, 8))
        cols = ("site", "status")
        self.site_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=5)
        self.site_tree.heading("site", text="SITE")
        self.site_tree.heading("status", text="STATUS")
        self.site_tree.column("site", width=280)
        self.site_tree.column("status", width=160)
        
        site_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.site_tree.yview)
        self.site_tree.configure(yscrollcommand=site_scroll.set)
        self.site_tree.pack(side="left", fill="both", expand=True)
        site_scroll.pack(side="right", fill="y")

        ttk.Label(self.tab_sites, text="IP blacklist (malicious data connections)").pack(anchor="w")
        iprow = ttk.Frame(self.tab_sites)
        iprow.pack(fill="x", pady=4)
        self.new_ip = tk.StringVar()
        ttk.Entry(iprow, textvariable=self.new_ip, width=22).pack(side="left")
        ttk.Button(iprow, text="Add IP", command=self._add_ip).pack(side="left", padx=6)
        ttk.Button(iprow, text="Remove IP", command=self._remove_ip).pack(side="left")
        
        ip_frame = ttk.Frame(self.tab_sites)
        ip_frame.pack(fill="x", pady=(4, 0))
        self.ip_list = tk.Listbox(ip_frame, height=3)
        ip_scroll = ttk.Scrollbar(ip_frame, orient="vertical", command=self.ip_list.yview)
        self.ip_list.configure(yscrollcommand=ip_scroll.set)
        self.ip_list.pack(side="left", fill="x", expand=True)
        ip_scroll.pack(side="right", fill="y")

        ttk.Label(
            self.tab_sites,
            text="Local / LAN addresses are never blacklisted. Only unsolicited inbound from foreign IPs.",
            wraplength=650,
        ).pack(anchor="w", fill="x", pady=(4, 4))

        malrow = ttk.Frame(self.tab_sites)
        malrow.pack(fill="x", pady=(8, 2))
        ttk.Label(malrow, text="Hidden malware files").pack(side="left")
        ttk.Button(malrow, text="Scan hidden files", command=self._scan_malware).pack(side="left", padx=8)
        ttk.Button(malrow, text="Delete listed files", command=self._delete_malware).pack(side="left")
        
        mal_frame = ttk.Frame(self.tab_sites)
        mal_frame.pack(fill="x")
        self.mal_list = tk.Listbox(mal_frame, height=3)
        mal_scroll = ttk.Scrollbar(mal_frame, orient="vertical", command=self.mal_list.yview)
        self.mal_list.configure(yscrollcommand=mal_scroll.set)
        self.mal_list.pack(side="left", fill="x", expand=True)
        mal_scroll.pack(side="right", fill="y")

        approw = ttk.Frame(self.tab_sites)
        approw.pack(fill="x", pady=(8, 2))
        ttk.Label(approw, text="Protected desktop apps").pack(side="left")
        ttk.Button(approw, text="Scan open apps", command=self._scan_apps).pack(side="left", padx=8)
        
        app_frame = ttk.Frame(self.tab_sites)
        app_frame.pack(fill="x")
        self.app_list = tk.Listbox(app_frame, height=3)
        app_scroll = ttk.Scrollbar(app_frame, orient="vertical", command=self.app_list.yview)
        self.app_list.configure(yscrollcommand=app_scroll.set)
        self.app_list.pack(side="left", fill="x", expand=True)
        app_scroll.pack(side="right", fill="y")
        
        self._reload_filter_ui()
    def _reload_filter_ui(self) -> None:
        for item in self.site_tree.get_children():
            self.site_tree.delete(item)
        for site in blocker.all_sites():
            status = "BLOCKED" if site.get("blocked") else "PROTECTED (AES)"
            self.site_tree.insert("", "end", values=(site.get("host"), status))
        self.ip_list.delete(0, "end")
        for ip in blocker.blocked_ips():
            self.ip_list.insert("end", ip)
        if hasattr(self, "app_list"):
            self.app_list.delete(0, "end")
            for name in apps.load_protected():
                self.app_list.insert("end", name)

    def _selected_site(self) -> str:
        item = self.site_tree.focus()
        if not item:
            return ""
        values = self.site_tree.item(item, "values")
        return values[0] if values else ""

    def _add_site(self) -> None:
        host = self.new_site.get().strip()
        if not host:
            return
        try:
            blocker.add_site(host)
        except ValueError as exc:
            self._log(str(exc))
            return
        persist.write_applied_and_save({"site_filter": True})
        self.new_site.set("")
        self._reload_filter_ui()
        self._log(f"Added to protection list: {host}")

    def _block_selected_site(self) -> None:
        host = self._selected_site()
        if not host:
            self._log("Select a site first.")
            return

        def work():
            blocker.set_site_blocked(host, True)
            persist.write_applied_and_save({"last_site_action": f"block {host}"})
            print(f"Blocked {host} (hosts + guard). Other listed sites stay AES-protected.")

        self._run(f"Block {host}", work)
        self._reload_filter_ui()

    def _unblock_selected_site(self) -> None:
        host = self._selected_site()
        if not host:
            self._log("Select a site first.")
            return

        def work():
            blocker.set_site_blocked(host, False)
            persist.write_applied_and_save({"last_site_action": f"unblock {host}"})
            print(f"Unblocked {host}. Connecting to it uses the AES HTTP/HTTPS tunnel.")

        self._run(f"Unblock {host}", work)
        self._reload_filter_ui()

    def _add_ip(self) -> None:
        ip = self.new_ip.get().strip()
        if not ip:
            return
        if blocker._is_local_or_lan_ip(ip):
            self._log(f"Refused to blacklist local/LAN address {ip}")
            self.new_ip.set("")
            return
        blocker.add_ip(ip)
        persist.write_applied_and_save({"ip_blacklist": blocker.blocked_ips()})
        self.new_ip.set("")
        self._reload_filter_ui()
        self._log(f"Blacklisted IP {ip}")

    def _scan_malware(self) -> None:
        import engine

        found = engine.scan_malware_files()
        self.mal_list.delete(0, "end")
        if not found:
            self.mal_list.insert("end", "(none found)")
            self._log("Hidden-file scan: no suspicious items.")
            return
        for item in found:
            self.mal_list.insert("end", f"{item['reason']}: {item['path']}")
        self._log(f"Hidden-file scan listed {len(found)} item(s) for deletion.")

    def _delete_malware(self) -> None:
        import engine

        results = engine.delete_malware()
        deleted = [r for r in results if r.get("deleted")]
        failed = [r for r in results if not r.get("deleted")]
        self.mal_list.delete(0, "end")
        for r in failed:
            self.mal_list.insert("end", f"KEEP {r.get('error')}: {r['path']}")
        if not failed:
            self.mal_list.insert("end", "(deleted)")
        self._log(f"Deleted {len(deleted)} file(s); {len(failed)} not removed.")

    def _remove_ip(self) -> None:
        sel = self.ip_list.curselection()
        if not sel:
            ip = self.new_ip.get().strip()
        else:
            ip = self.ip_list.get(sel[0])
        if not ip:
            return
        blocker.remove_ip(ip)
        persist.write_applied_and_save({"ip_blacklist": blocker.blocked_ips()})
        self._reload_filter_ui()
        self._log(f"Removed IP {ip}")

    def _scan_apps(self) -> None:
        names = apps.sync_open_apps()
        persist.write_applied_and_save({"protected_apps": names})
        self._reload_filter_ui()
        self._log("Protected desktop apps:\n  " + "\n  ".join(names or ["(none)"]))
    def _build_firewall(self) -> None:
        ttk.Label(
            self.tab_fw,
            text="Firewall modes. HTTP/HTTPS + VPN reads the current Windows Firewall profiles, keeps DHCP DNS protected, and binds the tunnel to the DHCP address.",
            wraplength=650,
        ).pack(anchor="w", fill="x")

        self.fw_mode = tk.StringVar(value="off")
        grid = ttk.Frame(self.tab_fw)
        grid.pack(fill="x", pady=10)

        modes = [
            ("lock", "LOCK — block inbound VPN/SQL, allow outbound"),
            ("vpn", "VPN ON — same blocks + allow local encrypted port"),
            ("http-https-vpn", "HTTP/HTTPS proxy + VPN monitor — 127.0.0.1:8080, VPN does not carry web"),
            ("inbound-only", "INBOUND-ONLY — cut outbound; encrypted listen port only"),
            ("off", "OFF — remove NetLock firewall rules"),
        ]
        for value, label in modes:
            ttk.Radiobutton(grid, text=label, variable=self.fw_mode, value=value).pack(anchor="w", pady=2)

        row = ttk.Frame(self.tab_fw)
        row.pack(fill="x", pady=6)
        ttk.Label(row, text="Tunnel UDP port").pack(side="left")
        self.port_var = tk.StringVar(value=str(netlock.DEFAULT_TUNNEL_PORT))
        ttk.Entry(row, textvariable=self.port_var, width=8).pack(side="left", padx=8)
        ttk.Label(row, text="Tunnel DNS").pack(side="left")
        self.dns_var = tk.StringVar(value=",".join(netlock.DEFAULT_TUNNEL_DNS))
        ttk.Entry(row, textvariable=self.dns_var, width=28).pack(side="left", padx=8)

        # Bottom interactive control row
        h_row = ttk.Frame(self.tab_fw)
        h_row.pack(fill="x", pady=4)
        ttk.Button(h_row, text="Apply firewall mode", command=self._apply_fw).pack(side="left", pady=6)
        ttk.Button(h_row, text="Run Encryption Hardening", command=self._trigger_hardening).pack(side="left", padx=10, pady=6)
        
        self.fw_status = ttk.Label(self.tab_fw, text="")
        self.fw_status.pack(anchor="w", pady=(8, 0))

    def _trigger_hardening(self) -> None:
        def work():
            lines = netlock.apply_encryption_hardening()
            for line in lines:
                print(line)
        self._run("System Policy Hardening", work)
    def _apply_fw(self) -> None:
        state = netlock.load_state()
        try:
            state["tunnel_port"] = int(self.port_var.get().strip() or netlock.DEFAULT_TUNNEL_PORT)
        except ValueError:
            messagebox.showerror("Port", "Tunnel port must be a number.")
            return
        dns = [p.strip() for p in self.dns_var.get().split(",") if p.strip()]
        if dns:
            state["tunnel_dns"] = dns
        netlock.save_state(state)
        mode = self.fw_mode.get()
        fn = {
            "lock": netlock.mode_lock,
            "vpn": netlock.mode_vpn_on,
            "http-https-vpn": netlock.mode_http_https_vpn,
            "inbound-only": netlock.mode_inbound_encrypted_only,
            "off": netlock.mode_off,
        }[mode]

        def work():
            import dhcp_bind

            bound = dhcp_bind.auto_bind_and_save()
            print(f"DHCP address: {bound.get('dhcp_ip')}  DNS: {bound.get('dhcp_dns')}")
            print(f"Firewall profiles: {bound.get('firewall_profiles')}")
            if mode == "http-https-vpn":
                print(dhcp_bind.apply_http_https_vpn(int(state.get("tunnel_port") or 51821)))
            elif fn:
                fn(state)
            persist.write_applied_and_save(
                {
                    "firewall_mode": mode,
                    "tunnel_port": state.get("tunnel_port"),
                    "tunnel_dns": bound.get("dhcp_dns") or state.get("tunnel_dns"),
                    "bind": bound.get("bind") or bound.get("dhcp_ip"),
                }
            )
            print(f"Applied data file: {persist.APPLIED_FILE}")
            print(f"Save file: {persist.SAVE_FILE}")
            print(f"Text save: {persist.SAVE_TEXT}")
            if mode in {"vpn", "http-https-vpn"}:
                try:
                    port = int(self.port_var.get().strip() or vpn_server.DEFAULT_PORT)
                except ValueError:
                    port = vpn_server.DEFAULT_PORT
                print(guard.start(tunnel_port=port)[1])
                flagged = guard.scan_and_act(kill=True, tunnel_port=port)
                print(f"SQL/VPN guard pass flagged {len(flagged)} sockets.")

        self._run(f"Firewall {mode}", work)
    def _build_vpn(self) -> None:
        ttk.Label(
            self.tab_vpn,
            text="Separate private and public AES-256-GCM tunnels. Private binds 192.x + loopback :51821 / SOCKS 1080. Public binds 0.0.0.0 :51822 / SOCKS 1081 with its own session key.",
            wraplength=650,
        ).pack(anchor="w", fill="x")

        row = ttk.Frame(self.tab_vpn)
        row.pack(fill="x", pady=10)
        ttk.Button(row, text="Generate server files", command=self._vpn_generate).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Start private tunnel", command=self._vpn_start).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Start public tunnel", command=self._vpn_start_public).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Stop private", command=self._vpn_stop_private).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Stop public", command=self._vpn_stop_public).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Stop all", command=self._vpn_stop).pack(side="left", padx=(0, 6))
        ttk.Button(row, text="Refresh status", command=self._refresh_all).pack(side="left")

        self.vpn_status = tk.Text(self.tab_vpn, height=10, wrap="word")
        self.vpn_status.pack(fill="both", expand=True, pady=(8, 0))

    def _vpn_generate(self) -> None:
        try:
            port = int(self.port_var.get().strip() or vpn_server.DEFAULT_PORT)
        except ValueError:
            port = vpn_server.DEFAULT_PORT
        dns = [p.strip() for p in self.dns_var.get().split(",") if p.strip()] or None

        def work():
            st = vpn_server.write_server_files(port=port, dns=dns)
            persist.write_applied_and_save(
                {
                    "tunnel_port": st.get("port", port),
                    "tunnel_dns": st.get("dns") or dns,
                    "socks_port": st.get("socks_port"),
                    "bind": st.get("bind"),
                }
            )
            print("Wrote server files, applied data, and save file.")
            print(f"Applied: {persist.APPLIED_FILE}")
            print(f"Save: {persist.SAVE_FILE}")
            print(f"Text save: {persist.SAVE_TEXT}")

        self._run("Generate VPN configs", work)
    def _vpn_start(self) -> None:
        def work():
            ok, msg = vpn_server.start_server()
            print(msg)
            try:
                port = int(self.port_var.get().strip() or vpn_server.DEFAULT_PORT)
            except ValueError:
                port = vpn_server.DEFAULT_PORT
            gok, gmsg = guard.start(tunnel_port=port)
            print(gmsg)
            print(app_proxy.start())
            persist.write_applied_and_save(
                {"vpn_running": bool(ok), "vpn_scope": "private", "http_guard": bool(gok)}
            )
            print(f"Applied: {persist.APPLIED_FILE}")
            print(f"Save: {persist.SAVE_FILE}")
            if not ok:
                print("Private server was not started.")

        self._run("Start private tunnel", work)

    def _vpn_start_public(self) -> None:
        def work():
            ok, msg = vpn_server.start_public_server()
            print(msg)
            persist.write_applied_and_save({"vpn_public_running": bool(ok), "vpn_scope_public": "public"})
            print(f"Applied: {persist.APPLIED_FILE}")
            if not ok:
                print("Public server was not started.")

        self._run("Start public tunnel", work)

    def _vpn_stop_private(self) -> None:
        def work():
            ok, msg = vpn_server.stop_private_server()
            print(msg)
            persist.write_applied_and_save({"vpn_running": False})

        self._run("Stop private tunnel", work)

    def _vpn_stop_public(self) -> None:
        def work():
            ok, msg = vpn_server.stop_public_server()
            print(msg)
            persist.write_applied_and_save({"vpn_public_running": False})

        self._run("Stop public tunnel", work)

    def _vpn_stop(self) -> None:
        def work():
            ok, msg = vpn_server.stop_server()
            print(msg)
            print(guard.stop()[1])
            print(app_proxy.stop())
            persist.write_applied_and_save({"vpn_running": False, "vpn_public_running": False, "http_guard": False})
            print(f"Applied: {persist.APPLIED_FILE}")
            print(f"Save: {persist.SAVE_FILE}")

    def _refresh_all(self) -> None:
        saved = persist.load_save()
        st = netlock.load_state()
        mode = saved.get("firewall_mode") or st.get("mode") or "off"
        port = saved.get("tunnel_port") or st.get("tunnel_port") or netlock.DEFAULT_TUNNEL_PORT
        dns = saved.get("tunnel_dns") or st.get("tunnel_dns") or netlock.DEFAULT_TUNNEL_DNS
        self.fw_mode.set(mode)
        self.port_var.set(str(port))
        self.dns_var.set(",".join(dns))
        self.fw_status.config(text=f"Current firewall mode: {mode}")
        extra = (
            f"\n\nApplied file: {persist.APPLIED_FILE}"
            f"\nSave file: {persist.SAVE_FILE}"
            f"\nLast save: {saved.get('updated_at')}"
            f"\nSites blocked: {saved.get('sites_blocked')}"
            f"\nVPN running flag: {saved.get('vpn_running')}"
        )
        self.vpn_status.delete("1.0", "end")
        self.vpn_status.insert("1.0", vpn_server.status_text() + extra)
    def _build_connections(self) -> None:
        ttk.Label(
            self.tab_conn,
            text="All sockets on this computer. The AES tunnel runs in parallel with an HTTP/HTTPS filter (127.0.0.1:8080). Guard tags blocked-host, SQL, and extra VPN sockets and can terminate them.",
            wraplength=650,
        ).pack(anchor="w", fill="x")
        row = ttk.Frame(self.tab_conn)
        row.pack(fill="x", pady=8)
        ttk.Button(row, text="Refresh connections", command=self._refresh_connections).pack(side="left")
        ttk.Button(row, text="Terminate selected", command=self._kill_selected).pack(side="left", padx=6)
        ttk.Button(row, text="Scan and terminate flagged", command=self._scan_kill).pack(side="left", padx=6)
        self.conn_count = ttk.Label(row, text="")
        self.conn_count.pack(side="left", padx=12)

        cols = ("proto", "state", "local", "remote", "pid", "app", "tag")
        self.conn_tree = ttk.Treeview(self.tab_conn, columns=cols, show="headings", height=6)
        for col, width in (
            ("proto", 55),
            ("state", 90),
            ("local", 130),
            ("remote", 130),
            ("pid", 55),
            ("app", 120),
            ("tag", 90),
        ):
            self.conn_tree.heading(col, text=col.upper())
            self.conn_tree.column(col, width=width, stretch=True)
        scroll = ttk.Scrollbar(self.tab_conn, orient="vertical", command=self.conn_tree.yview)
        self.conn_tree.configure(yscrollcommand=scroll.set)
        box = ttk.Frame(self.tab_conn)
        box.pack(fill="both", expand=True)
        self.conn_tree.pack(in_=box, side="left", fill="both", expand=True)
        scroll.pack(in_=box, side="right", fill="y")

        ttk.Label(self.tab_conn, text="IP connections and running app").pack(anchor="w", pady=(8, 2))
        self.ip_app = scrolledtext.ScrolledText(self.tab_conn, height=6, wrap="none")
        self.ip_app.pack(fill="both", expand=True)
    def _refresh_connections(self) -> None:
        for item in self.conn_tree.get_children():
            self.conn_tree.delete(item)
        try:
            rows = connections.list_connections()
        except Exception as exc:
            self.conn_count.config(text=str(exc))
            self._log(f"Connection list failed: {exc}")
            return
        try:
            port = int(self.port_var.get().strip() or 51821)
        except Exception:
            port = 51821
        guard.refresh_blocklist()
        flagged = 0
        lines = ["IP / remote                  App                         PID    Tag"]
        for r in rows:
            tag = guard.classify(r, tunnel_port=port)
            if tag != "ok":
                flagged += 1
            self.conn_tree.insert(
                "",
                "end",
                values=(
                    r.get("proto"),
                    r.get("state"),
                    r.get("local"),
                    r.get("remote"),
                    r.get("pid"),
                    r.get("app") or "",
                    tag,
                ),
            )
            remote = r.get("remote") or ""
            if remote not in {"*:*", "0.0.0.0:0", "[::]:0", ""}:
                lines.append(
                    f"{remote:<28} {(r.get('app') or '(unknown)'):<27} {str(r.get('pid') or '-'):<6} {tag}"
                )
        self.ip_app.delete("1.0", "end")
        self.ip_app.insert("1.0", "\n".join(lines) if len(lines) > 1 else "No remote IP connections.")
        gstate = "guard on" if guard.running() else "guard off"
        self.conn_count.config(text=f"{len(rows)} sockets, {flagged} flagged, {gstate}")

    def _kill_selected(self) -> None:
        item = self.conn_tree.focus()
        if not item:
            self._log("Select a connection first.")
            return
        values = self.conn_tree.item(item, "values")
        pid = values[4] if len(values) > 4 else ""
        ok, msg = guard.terminate_pid(pid)
        self._log(f"Terminate PID {pid}: {msg}" if ok else f"Could not terminate {pid}: {msg}")
        self._refresh_connections()

    def _scan_kill(self) -> None:
        try:
            port = int(self.port_var.get().strip() or 51821)
        except Exception:
            port = 51821
        flagged = guard.scan_and_act(kill=True, tunnel_port=port)
        self._log(f"Flagged {len(flagged)} sockets; attempted terminate on blocked/sql/vpn tags.")
        for row in flagged[:20]:
            self._log(f"  {row.get('tag')} {row.get('local')} -> {row.get('remote')} pid={row.get('pid')} {row.get('action','')}")
        self._refresh_connections()
    def _boot_shield(self) -> None:
        """On launch: bind LAN + gateway into VPN+SQL shield and force HTTP/HTTPS through AES."""
        self._log("--- Launch shield ---")
        
        # Enforce encryption profiles across target network interfaces during validation phases
        if self.admin:
            self._log("Enforcing active transport encryption policies...")
            hardening_results = netlock.apply_encryption_hardening()
            for log_entry in hardening_results:
                self._log(f"  {log_entry}")

        info = network_boot.local_and_gateway()
        persist.write_applied_and_save(
            {
                "local_ip": info.get("local_ip"),
                "gateway": info.get("gateway"),
                "adapter": info.get("adapter"),
                "connection_kind": info.get("kind"),
                "broadband_target": info.get("broadband_target"),
                "broadband_port": info.get("broadband_port"),
                "tunnel_dns": info.get("dns") or [],
            }
        )
        self._log(f"Local IPv4: {info.get('local_ip') or '(none)'}")
        self._log(f"Gateway:    {info.get('gateway') or '(none)'}")
        self._log(f"Adapter:    {info.get('adapter') or '(unknown)'}")
        self._log(f"Kind:       {info.get('kind') or '(unknown)'}")
        if info.get("internet_ok"):
            self._log(
                f"Broadband:  {info.get('broadband_target')}:{info.get('broadband_port')} "
                f"on {info.get('kind')}"
            )
        if info.get("dns"):
            self.dns_var.set(",".join(info["dns"]))
        try:
            import dhcp_bind

            bound = dhcp_bind.auto_bind_and_save()
            self._log(f"DHCP bind: {bound.get('dhcp_ip') or '(none)'}")
            self._log(f"Protected DNS: {', '.join(bound.get('protected_dns') or []) or '(none)'}")
            if bound.get("dhcp_dns"):
                self.dns_var.set(",".join(bound["dhcp_dns"]))
            
            try:
                p_val = int(self.port_var.get().strip() or 51821)
            except ValueError:
                p_val = 51821
            print(dhcp_bind.apply_http_https_vpn(p_val))
            self.fw_mode.set("http-https-vpn")
        except Exception as exc:
            self._log(f"DHCP bind skipped: {exc}")

        state = netlock.load_state()
        try:
            state["tunnel_port"] = int(self.port_var.get().strip() or netlock.DEFAULT_TUNNEL_PORT)
        except Exception:
            state["tunnel_port"] = netlock.DEFAULT_TUNNEL_PORT
        dns = [p.strip() for p in self.dns_var.get().split(",") if p.strip()]
        if dns:
            state["tunnel_dns"] = dns
        if info.get("kind") == "pdanet":
            self._log("PdaNet detected — using the established tether as the Internet path.")
        elif str(info.get("kind") or "").startswith("modem_router"):
            self._log("Modem/router detected — auto-filled local IP, gateway, and DNS.")
        netlock.save_state(state)

        def work():
            print("VPN server stays OFF until you press Start VPN server.")
            dok, dmsg = wintun_tun.install_driver()
            print(dmsg)
            print(wintun_tun.assign_broadband_ip(info.get("local_ip") or "", info.get("gateway") or "", ""))
            print(app_proxy.start())
            print(guard.start_inbound_watch()[1])
            # Browser system proxy -> local 8080. Guard HTTP listener starts with the VPN.
            print(guard.set_system_proxy(True))
            persist.write_applied_and_save(
                {
                    "vpn_running": False,
                    "http_guard": False,
                    "shield_http_https": False,
                    "local_ip": info.get("local_ip"),
                    "gateway": info.get("gateway"),
                    "adapter": info.get("adapter"),
                    "bind": info.get("local_ip") if str(info.get("local_ip") or "").startswith("192.") else persist.load_applied().get("bind"),
                    "connection_kind": info.get("kind"),
                    "wintun_driver": dmsg,
                }
            )
            print("Browser proxy set to 127.0.0.1:8080 (not routed through the VPN).")
            print("VPN monitors connectivity and intercepts malicious sockets in parallel.")
            print("Open apps get a temporary 127.0.0.1 proxy; closing the app drops that proxy.")
            print("PdaNet/modem-router 192.x address was applied to NetLockTUN (LAN IP, not NIC name).")

        self._run("Prepare driver, PdaNet/router IP, browser + app proxies (server OFF)", work)
    def _poll_stream(self) -> None:
        try:
            import netlock_net
            import stream

            rec = persist.load_applied()
            stream.poll_nic()
            ip = rec.get("dhcp_ip") or rec.get("bind") or rec.get("local_ip") or ""
            port = rec.get("broadband_port") or 8000
            attached = rec.get("c_net") or {}
            if not attached.get("ok") and ip:
                attached = netlock_net.attach_existing_broadband(str(ip), int(port))
            snap = stream.snapshot(60)
            self.stream_status.config(
                text=(
                    f"Upload {snap.get('upload', '0 bps')}   "
                    f"Download {snap.get('download', '0 bps')}   "
                    f"total ↑{snap['bytes_up']} B  ↓{snap['bytes_down']} B   "
                    f"bind {attached.get('ip') or ip}:{attached.get('port') or port}   "
                    f"ok={attached.get('ok')}"
                )
            )
            body = "\n".join(snap["lines"])
            current = self.stream.get("1.0", "end-1c")
            if body != current:
                self.stream.delete("1.0", "end")
                self.stream.insert("1.0", body or "(waiting for traffic)")
                self.stream.see("end")
        except Exception as exc:
            self.stream_status.config(text=f"stream error: {exc}")
        self.after(800, self._poll_stream)

    def _poll_link(self) -> None:
        try:
            info = vpn_server.link_status()
            label = info.get("label") or "DEAD"
            self.link_label.config(text=f"OUTSIDE: {label}")
        except Exception:
            self.link_label.config(text="OUTSIDE: DEAD")
        self.after(8000, self._poll_link)

    def _on_tab(self, _event=None) -> None:
        try:
            current = self.nb.tab(self.nb.select(), "text")
        except Exception:
            return
        if current == "All connections":
            self._refresh_connections()


def main() -> int:
    try:
        app = NetLockApp()
    except Exception:
        traceback.print_exc()
        try:
            messagebox.showerror("NetLock", traceback.format_exc())
        except Exception:
            pass
        return 1
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
