import socket
import ssl
import threading
import json
import os
import random
import string
import datetime
import tkinter
import tkinter.scrolledtext
import tkinter.messagebox

# ==========================================
# КРИПТОГРАФИЯ ДЛЯ СЕРТИФИКАТОВ
# ==========================================
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from cryptography.x509 import SubjectAlternativeName, DNSName
    HAS_SAN = True
except ImportError:
    HAS_SAN = False

# ==========================================
# НАСТРОЙКИ И ЦВЕТА
# ==========================================
HOST = '0.0.0.0'
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'

BG_COLOR = "#2b2b2b"
FG_COLOR = "#ffffff"
INPUT_BG = "#3c3c3c"
INPUT_FG = "#ffffff"
TEXT_BG = "#1e1e1e"
SERVER_COLOR = "#569cd6"
CLIENT_COLOR = "#6a9955"
SYSTEM_COLOR = "#ce9178"
DM_COLOR = "#d7ba7d"
HELP_COLOR = "#4ec9b0"
ERROR_COLOR = "#f44747"

MAX_TEXT_LEN = 4000
MAX_NICK_LEN = 24
RECV_BUFFER = 65536
MAX_BUFFER = 1 << 20  # 1 MB
PING_INTERVAL_MS = 30000  # интервал пинга клиента (мс)


# ==========================================
# СЕРТИФИКАТЫ
# ==========================================
def ensure_certificates():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return True
    if not HAS_CRYPTO:
        return False
    try:
        rand_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"RU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"GFN_{rand_id}"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        )
        if HAS_SAN:
            builder = builder.add_extension(
                SubjectAlternativeName([DNSName(u"localhost")]),
                critical=False,
            )
        cert = builder.sign(key, hashes.SHA256())

        with open(KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        return True
    except Exception as e:
        print(f"Ошибка создания сертификата: {e}")
        return False


# ==========================================
# ФРЕЙМИНГ TCP (JSON + \n)
# ==========================================
def send_packet(sock, packet):
    data = json.dumps(packet, ensure_ascii=False) + "\n"
    sock.sendall(data.encode('utf-8'))


class PacketReader:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = ""

    def read(self):
        while "\n" not in self.buffer:
            chunk = self.sock.recv(RECV_BUFFER)
            if not chunk:
                return None
            self.buffer += chunk.decode('utf-8', errors='replace')
            if len(self.buffer) > MAX_BUFFER:
                raise ValueError("Слишком большой пакет")
        line, self.buffer = self.buffer.split("\n", 1)
        line = line.strip()
        if not line:
            return self.read()
        return json.loads(line)


# ==========================================
# КЛАСС СЕРВЕРА
# ==========================================
class ChatServer:
    def __init__(self, port, server_nick, on_message_callback,
                 on_user_update, on_channel_update):
        self.clients = {}
        self.channels = {"#general": set()}
        self.lock = threading.Lock()
        self.send_locks = {}  # блокировка отправки на каждого клиента
        self.port = port
        self.server_nick = server_nick
        self.on_message_callback = on_message_callback
        self.on_user_update = on_user_update
        self.on_channel_update = on_channel_update
        self.running = True
        self.socket = None
        self.ssl_context = None

    def start(self):
        try:
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((HOST, self.port))
            self.socket.listen(10)

            self.on_message_callback("SYSTEM", "Server started. Waiting for clients...",
                                     SYSTEM_COLOR)
            while self.running:
                try:
                    conn, addr = self.socket.accept()
                except OSError:
                    break
                try:
                    ssl_conn = self.ssl_context.wrap_socket(conn, server_side=True)
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    continue
                threading.Thread(target=self.handle_client,
                                 args=(ssl_conn, addr), daemon=True).start()
        except Exception as e:
            self.on_message_callback("SYSTEM", f"Server error: {e}", ERROR_COLOR)

    def handle_client(self, conn, addr):
        nick = None
        registered = False
        reader = PacketReader(conn)
        try:
            packet = reader.read()
            if not packet:
                return
            nick = packet.get("nick")
            if not isinstance(nick, str):
                return
            nick = nick.strip()
            if not nick or len(nick) > MAX_NICK_LEN or " " in nick:
                send_packet(conn, {"type": "error", "text": "Invalid nickname"})
                return

            with self.lock:
                occupied = nick in self.clients or nick == self.server_nick
                if not occupied:
                    self.clients[nick] = conn
                    self.channels["#general"].add(nick)
                    self.send_locks[nick] = threading.Lock()
                    registered = True

            if occupied:
                send_packet(conn, {"type": "error", "text": "Nickname already taken"})
                return

            self.on_message_callback("SYSTEM", f"{nick} connected.", SYSTEM_COLOR)
            self.broadcast_user_list()
            self.send_channel_list(conn, nick)
            self.broadcast("SERVER", "#general", f"*** {nick} joined the chat ***")

            while self.running:
                packet = reader.read()
                if packet is None:
                    break
                if not isinstance(packet, dict):
                    continue
                action = packet.get("action")

                if action == "ping":
                    # служебный пакет для поддержания соединения — игнорируем
                    continue

                elif action == "join":
                    channel = packet.get("channel")
                    if not isinstance(channel, str) or not channel.startswith("#") \
                            or " " in channel or len(channel) < 2:
                        continue
                    with self.lock:
                        if channel not in self.channels:
                            self.channels[channel] = set()
                        self.channels[channel].add(nick)
                    self.broadcast_channel_list()
                    self.on_message_callback("SYSTEM", f"{nick} moved to {channel}",
                                             SYSTEM_COLOR)

                elif action == "leave":
                    channel = packet.get("channel")
                    if not isinstance(channel, str):
                        continue
                    with self.lock:
                        if channel in self.channels:
                            self.channels[channel].discard(nick)

                elif action == "msg":
                    target = packet.get("target")
                    text = packet.get("text")
                    if not isinstance(target, str) or not isinstance(text, str):
                        continue
                    text = text[:MAX_TEXT_LEN]
                    if not text.strip():
                        continue
                    self.broadcast(nick, target, text)
                    self.on_message_callback(nick, text, SERVER_COLOR, target)

                elif action == "create":
                    if nick == self.server_nick:
                        channel = packet.get("channel")
                        if isinstance(channel, str) and channel.startswith("#") \
                                and " " not in channel and len(channel) >= 2:
                            self.create_channel(channel)

        except Exception:
            pass
        finally:
            if registered and nick:
                with self.lock:
                    self.clients.pop(nick, None)
                    self.send_locks.pop(nick, None)
                    for chan in self.channels.values():
                        chan.discard(nick)
                self.broadcast_user_list()
                self.broadcast("SERVER", "#general", f"*** {nick} left the chat ***")
                self.on_message_callback("SYSTEM", f"{nick} disconnected.", SYSTEM_COLOR)
            try:
                conn.close()
            except Exception:
                pass

    def create_channel(self, channel):
        with self.lock:
            if channel in self.channels:
                return False
            self.channels[channel] = set()
        self.broadcast_channel_list()
        return True

    def send_locked(self, nick, sock, packet):
        """Отправка пакета под личной блокировкой клиента (потокобезопасно)."""
        lock = self.send_locks.get(nick)
        if lock:
            with lock:
                send_packet(sock, packet)
        else:
            send_packet(sock, packet)

    def broadcast(self, sender, target, text):
        packet = {"type": "msg", "sender": sender, "target": target, "text": text}
        with self.lock:
            if target.startswith("#"):
                recipients = [(n, self.clients[n])
                              for n in self.channels.get(target, set())
                              if n in self.clients and n != sender]
            else:
                if target in self.clients and target != sender:
                    recipients = [(target, self.clients[target])]
                else:
                    recipients = []
        for nick_, sock in recipients:
            try:
                self.send_locked(nick_, sock, packet)
            except Exception:
                pass

    def broadcast_user_list(self):
        with self.lock:
            users = [self.server_nick] + sorted(self.clients.keys())
            socks = list(self.clients.items())
        packet = {"type": "userlist", "users": users}
        for nick_, sock in socks:
            try:
                self.send_locked(nick_, sock, packet)
            except Exception:
                pass
        self.on_user_update(users)

    def broadcast_channel_list(self):
        with self.lock:
            channels = sorted(self.channels.keys())
            socks = list(self.clients.items())
        packet = {"type": "channellist", "channels": channels}
        for nick_, sock in socks:
            try:
                self.send_locked(nick_, sock, packet)
            except Exception:
                pass
        self.on_channel_update(channels)

    def send_channel_list(self, conn, nick=None):
        with self.lock:
            channels = sorted(self.channels.keys())
        try:
            if nick:
                self.send_locked(nick, conn,
                                 {"type": "channellist", "channels": channels})
            else:
                send_packet(conn, {"type": "channellist", "channels": channels})
        except Exception:
            pass

    def stop(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        with self.lock:
            socks = list(self.clients.values())
        for sock in socks:
            try:
                sock.close()
            except Exception:
                pass


# ==========================================
# GUI
# ==========================================
class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GFN Messenger")
        self.root.geometry("750x550")
        self.root.configure(bg=BG_COLOR)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.nickname = tkinter.StringVar(value="User")
        self.server_ip = tkinter.StringVar(value="127.0.0.1")
        self.port = tkinter.StringVar(value="7777")

        self.is_server = False
        self.socket = None
        self.reader = None
        self.is_connected = False
        self.current_channel = "#general"
        self.server_instance = None
        self.reconnect_btn = None
        self._ping_generation = 0

        self.chat_area = None
        self.msg_entry = None
        self.user_listbox = None
        self.channel_listbox = None

        self.setup_login_ui()

    # ---------- UI ----------
    def setup_login_ui(self):
        self.clear_ui()
        frame = tkinter.Frame(self.root, bg=BG_COLOR)
        frame.pack(expand=True)

        tkinter.Label(frame, text="GFN MESSENGER", bg=BG_COLOR, fg="#6a9955",
                      font=("Arial", 18, "bold")).pack(pady=20)

        for text, var in [("Nick:", self.nickname),
                          ("IP:", self.server_ip),
                          ("Port:", self.port)]:
            row = tkinter.Frame(frame, bg=BG_COLOR)
            row.pack(fill="x", pady=5)
            tkinter.Label(row, text=text, bg=BG_COLOR, fg=FG_COLOR,
                          width=8).pack(side=tkinter.LEFT)
            tkinter.Entry(row, textvariable=var, bg=INPUT_BG, fg=INPUT_FG).pack(
                side=tkinter.LEFT, fill="x", expand=True)

        tkinter.Button(frame, text="Start Server",
                       command=self.start_server_mode,
                       bg=INPUT_BG, fg=INPUT_FG, width=20).pack(pady=10)
        tkinter.Button(frame, text="Connect (Client)",
                       command=self.start_client_mode,
                       bg=INPUT_BG, fg=INPUT_FG, width=20).pack(pady=5)

    def setup_chat_ui(self):
        self.clear_ui()

        left_panel = tkinter.Frame(self.root, bg=BG_COLOR, width=160)
        left_panel.pack(side=tkinter.LEFT, fill=tkinter.Y, padx=5, pady=5)
        left_panel.pack_propagate(False)

        tkinter.Button(left_panel, text="Disconnect",
                       command=self.return_to_login,
                       bg=INPUT_BG, fg=INPUT_FG).pack(side=tkinter.BOTTOM,
                                                       fill=tkinter.X, pady=(5, 0))

        tkinter.Label(left_panel, text="Channels", bg=BG_COLOR, fg=SYSTEM_COLOR,
                      font=("Arial", 10, "bold")).pack(anchor="w")
        self.channel_listbox = tkinter.Listbox(left_panel, bg=INPUT_BG,
                                              fg=FG_COLOR, height=8)
        self.channel_listbox.pack(fill=tkinter.X, pady=(0, 10))
        self.channel_listbox.bind("<Double-Button-1>", self.on_channel_double_click)

        tkinter.Label(left_panel, text="Online", bg=BG_COLOR, fg=SYSTEM_COLOR,
                      font=("Arial", 10, "bold")).pack(anchor="w")
        self.user_listbox = tkinter.Listbox(left_panel, bg=INPUT_BG, fg=FG_COLOR)
        self.user_listbox.pack(fill=tkinter.BOTH, expand=True)
        self.user_listbox.bind("<Double-Button-1>", self.on_user_double_click)

        right_panel = tkinter.Frame(self.root, bg=BG_COLOR)
        right_panel.pack(side=tkinter.RIGHT, fill=tkinter.BOTH,
                         expand=True, padx=5, pady=5)

        self.chat_area = tkinter.scrolledtext.ScrolledText(
            right_panel, wrap=tkinter.WORD, bg=TEXT_BG, fg=FG_COLOR,
            state=tkinter.DISABLED)
        self.chat_area.pack(fill=tkinter.BOTH, expand=True)
        self.chat_area.tag_config("system", foreground=SYSTEM_COLOR)
        self.chat_area.tag_config("me", foreground=FG_COLOR)
        self.chat_area.tag_config("dm", foreground=DM_COLOR)
        self.chat_area.tag_config("other", foreground=SERVER_COLOR)
        self.chat_area.tag_config("help", foreground=HELP_COLOR)
        self.chat_area.tag_config("error", foreground=ERROR_COLOR)

        input_frame = tkinter.Frame(right_panel, bg=BG_COLOR)
        input_frame.pack(fill=tkinter.X, pady=(5, 0))

        self.msg_entry = tkinter.Entry(input_frame, bg=INPUT_BG, fg=INPUT_FG)
        self.msg_entry.pack(side=tkinter.LEFT, fill=tkinter.X, expand=True)
        self.msg_entry.bind("<Return>", self.send_message)

        self.reconnect_btn = tkinter.Button(input_frame, text="Reconnect",
                                            command=self.attempt_reconnect,
                                            bg=INPUT_BG, fg=INPUT_FG)
        # кнопка переподключения — показывается только при потере соединения

        tkinter.Button(input_frame, text="Send",
                       command=self.send_message,
                       bg=INPUT_BG, fg=INPUT_FG).pack(side=tkinter.RIGHT,
                                                       padx=(5, 0))

        self.root.title(f"GFN Messenger - [{self.current_channel}]")
        self.append_chat(f"[SYSTEM] You joined as {self.nickname.get()}\n", "system")
        self.append_chat("[SYSTEM] Type /help for the command list.\n", "system")

    def clear_ui(self):
        for w in self.root.winfo_children():
            w.destroy()
        self.chat_area = None
        self.msg_entry = None
        self.user_listbox = None
        self.channel_listbox = None
        self.reconnect_btn = None

    # ---------- утилиты ----------
    def get_port(self):
        try:
            p = int(self.port.get())
            if 1 <= p <= 65535:
                return p
        except (ValueError, tkinter.TclError):
            pass
        return None

    def validate_nick(self):
        nick = self.nickname.get().strip()
        if not nick:
            tkinter.messagebox.showerror("Error", "Enter a nickname!")
            return None
        if len(nick) > MAX_NICK_LEN or " " in nick:
            tkinter.messagebox.showerror(
                "Error", f"Nickname: up to {MAX_NICK_LEN} characters, no spaces.")
            return None
        return nick

    # ---------- выход в главное меню ----------
    def return_to_login(self):
        try:
            self.is_connected = False
            if self.server_instance:
                self.server_instance.stop()
            self.server_instance = None
            if self.socket:
                try:
                    self.socket.close()
                except Exception:
                    pass
            self.socket = None
            self.reader = None
            self.is_server = False
            self.current_channel = "#general"
        finally:
            self.setup_login_ui()

    # ---------- сервер ----------
    def start_server_mode(self):
        nick = self.validate_nick()
        if not nick:
            return
        port = self.get_port()
        if port is None:
            tkinter.messagebox.showerror("Error", "Invalid port!")
            return
        if not ensure_certificates():
            tkinter.messagebox.showerror(
                "Error",
                "Failed to create SSL certificates!\n"
                "Install: pip install cryptography")
            return

        self.is_server = True
        self.is_connected = True
        self.current_channel = "#general"
        self.setup_chat_ui()

        self._update_user_list_ui([nick])
        self._update_channel_listbox(["#general"])

        self.server_instance = ChatServer(
            port, nick,
            self.server_callback,
            self.update_user_list,
            self.update_channels,
        )
        threading.Thread(target=self.server_instance.start, daemon=True).start()

    def server_callback(self, sender, text, color, target="#general"):
        if sender == "SYSTEM":
            self.append_chat(f"[SYSTEM] {text}\n", "system")
        else:
            if target.startswith("#"):
                if target == self.current_channel:
                    self.append_chat(f"{sender}: {text}\n", "other")
            else:
                self.append_chat(f"[DM from {sender}] {text}\n", "dm")

    def update_channels(self, channels):
        self.root.after(0, self._update_channel_listbox, list(channels))

    # ---------- клиент ----------
    def start_client_mode(self):
        nick = self.validate_nick()
        if not nick:
            return
        port = self.get_port()
        if port is None:
            tkinter.messagebox.showerror("Error", "Invalid port!")
            return
        self.try_connect(nick, port)

    def try_connect(self, nick, port):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            raw_sock = socket.create_connection(
                (self.server_ip.get(), port), timeout=10)
            # ФИКС: таймаут нужен был только для подключения.
            # Снимаем его, иначе recv() падает по таймауту и выкидывает из чата.
            raw_sock.settimeout(None)
            self.socket = context.wrap_socket(
                raw_sock, server_hostname=self.server_ip.get())
            self.reader = PacketReader(self.socket)

            send_packet(self.socket, {"nick": nick})

            self.is_connected = True
            self.current_channel = "#general"
            self.setup_chat_ui()
            threading.Thread(target=self.receive_messages, daemon=True).start()
            self.start_ping()
            return True
        except Exception as e:
            self.is_connected = False
            self.socket = None
            self.reader = None
            tkinter.messagebox.showerror("Error",
                                         f"Connection failed:\n{e}")
            return False

    def attempt_reconnect(self):
        """Переподключение клиента к серверу с теми же настройками."""
        if self.is_server:
            return
        try:
            if self.socket:
                self.socket.close()
        except Exception:
            pass
        self.socket = None
        self.reader = None
        port = self.get_port()
        if port is None:
            tkinter.messagebox.showerror("Error", "Invalid port!")
            return
        nick = self.nickname.get().strip() or "User"
        self.try_connect(nick, port)

    def show_reconnect(self):
        """Показать кнопку переподключения после потери связи."""
        def _show():
            if (not self.is_connected and not self.is_server
                    and self.reconnect_btn is not None
                    and not self.msg_entry is None):
                self.reconnect_btn.pack(side=tkinter.RIGHT)
        self.root.after(0, _show)

    def start_ping(self):
        """Раз в 30 секунд шлём пустышку, чтобы соединение не умирало в простое."""
        self._ping_generation += 1
        gen = self._ping_generation

        def ping():
            if self._ping_generation != gen:
                return
            if self.is_connected:
                if not self.is_server:
                    self.send_raw({"action": "ping"})
                self.root.after(PING_INTERVAL_MS, ping)
        self.root.after(PING_INTERVAL_MS, ping)

    def receive_messages(self):
        while self.is_connected and self.reader:
            try:
                packet = self.reader.read()
            except Exception:
                break
            if packet is None:
                break
            if not isinstance(packet, dict):
                continue
            ptype = packet.get("type")

            if ptype == "userlist":
                self.update_user_list(packet.get("users", []))
            elif ptype == "channellist":
                self.update_channels(packet.get("channels", []))
            elif ptype == "msg":
                sender = packet.get("sender", "?")
                target = packet.get("target", "")
                text = packet.get("text", "")
                if not target.startswith("#"):
                    self.append_chat(f"[DM from {sender}] {text}\n", "dm")
                else:
                    if target != self.current_channel:
                        continue
                    if sender == self.nickname.get():
                        self.append_chat(f"You: {text}\n", "me")
                    else:
                        self.append_chat(f"{sender}: {text}\n", "other")
            elif ptype == "error":
                self.append_chat(
                    f"[ERROR] {packet.get('text', 'Error')}\n", "error")
                self.is_connected = False
                self.show_reconnect()
                break

        if self.is_connected:
            self.is_connected = False
            self.append_chat("[SYSTEM] Connection lost.\n", "error")
            self.show_reconnect()

    # ---------- обновление списков ----------
    def update_user_list(self, users):
        self.root.after(0, self._update_user_list_ui, list(users))

    def _update_user_list_ui(self, users):
        if not self.user_listbox:
            return
        self.user_listbox.delete(0, tkinter.END)
        for u in users:
            self.user_listbox.insert(tkinter.END, u)

    def _update_channel_listbox(self, channels):
        if not self.channel_listbox:
            return
        self.channel_listbox.delete(0, tkinter.END)
        for ch in sorted(channels):
            self.channel_listbox.insert(tkinter.END, ch)

    # ---------- чат ----------
    def append_chat(self, text, tag):
        self.root.after(0, self._append_chat_ui, text, tag)

    def _append_chat_ui(self, text, tag):
        if not self.chat_area:
            return
        self.chat_area.config(state=tkinter.NORMAL)
        self.chat_area.insert(tkinter.END, text, tag)
        self.chat_area.see(tkinter.END)
        self.chat_area.config(state=tkinter.DISABLED)

    def send_raw(self, packet):
        if self.is_server and self.server_instance:
            return True
        try:
            if self.socket:
                send_packet(self.socket, packet)
                return True
        except Exception as e:
            self.append_chat(f"[SYSTEM] Send error: {e}\n", "error")
            self.is_connected = False
            self.show_reconnect()
        return False

    def send_message(self, event=None):
        if not self.is_connected or not self.msg_entry:
            return
        text = self.msg_entry.get().strip()
        if not text:
            return
        self.msg_entry.delete(0, tkinter.END)
        nick = self.nickname.get()

        # ---- КОМАНДЫ ----
        if text.startswith("/"):
            parts = text.split(maxsplit=2)
            cmd = parts[0].lower()

            if cmd == "/help":
                help_text = (
                    "\n--- AVAILABLE COMMANDS ---\n"
                    "/help - Show this message\n"
                    "/join #channel - Join a channel (creates it if missing)\n"
                    "/create #channel - Create a channel (server only)\n"
                    "/msg Nick Text - Send a private message\n"
                    "/users - Show the online list\n"
                    "/channels - Show the channel list\n"
                    "--------------------------\n"
                )
                self.append_chat(help_text, "help")
                return

            elif cmd == "/join" and len(parts) > 1:
                ch = parts[1] if parts[1].startswith("#") else "#" + parts[1]
                if " " in ch or len(ch) < 2:
                    self.append_chat("[SYSTEM] Invalid channel name.\n", "error")
                    return
                old = self.current_channel
                if self.is_server and self.server_instance:
                    with self.server_instance.lock:
                        if ch not in self.server_instance.channels:
                            self.server_instance.channels[ch] = set()
                        self.server_instance.channels[ch].add(nick)
                        if old in self.server_instance.channels:
                            self.server_instance.channels[old].discard(nick)
                    self.server_instance.broadcast_channel_list()
                else:
                    if old != ch:
                        self.send_raw({"action": "leave", "channel": old})
                    self.send_raw({"action": "join", "channel": ch})
                self.current_channel = ch
                self.root.title(f"GFN Messenger - [{ch}]")
                self.append_chat(f"[SYSTEM] You moved to {ch}\n", "system")

            elif cmd == "/create" and len(parts) > 1:
                if not self.is_server:
                    self.append_chat(
                        "[SYSTEM] Only the server can create channels!\n", "error")
                    return
                ch = parts[1] if parts[1].startswith("#") else "#" + parts[1]
                if " " in ch or len(ch) < 2:
                    self.append_chat("[SYSTEM] Invalid channel name.\n", "error")
                    return
                if self.server_instance and self.server_instance.create_channel(ch):
                    self.append_chat(f"[SYSTEM] Channel {ch} created.\n", "system")
                else:
                    self.append_chat(f"[SYSTEM] Channel {ch} already exists.\n", "error")

            elif cmd == "/msg" and len(parts) > 2:
                target = parts[1]
                msg = parts[2][:MAX_TEXT_LEN]
                if self.is_server and self.server_instance:
                    self.server_instance.broadcast(nick, target, msg)
                    self.append_chat(f"[DM to {target}] {msg}\n", "dm")
                else:
                    if self.send_raw({"action": "msg",
                                      "target": target, "text": msg}):
                        self.append_chat(f"[DM to {target}] {msg}\n", "dm")

            elif cmd == "/users":
                if self.user_listbox:
                    users = [self.user_listbox.get(i)
                             for i in range(self.user_listbox.size())]
                    self.append_chat(
                        f"[SYSTEM] Online ({len(users)}): {', '.join(users)}\n",
                        "system")

            elif cmd == "/channels":
                if self.channel_listbox:
                    chans = [self.channel_listbox.get(i)
                             for i in range(self.channel_listbox.size())]
                    self.append_chat(
                        f"[SYSTEM] Channels ({len(chans)}): {', '.join(chans)}\n",
                        "system")

            else:
                self.append_chat(
                    f"[SYSTEM] Unknown command: {cmd}. Type /help\n",
                    "error")
            return

        # ---- ОБЫЧНОЕ СООБЩЕНИЕ ----
        text = text[:MAX_TEXT_LEN]
        if self.is_server and self.server_instance:
            self.server_instance.broadcast(nick, self.current_channel, text)
            self.append_chat(f"You: {text}\n", "me")
        else:
            if self.send_raw({"action": "msg",
                              "target": self.current_channel,
                              "text": text}):
                self.append_chat(f"You: {text}\n", "me")

    def on_channel_double_click(self, event):
        sel = self.channel_listbox.curselection()
        if not sel:
            return
        ch = self.channel_listbox.get(sel[0])
        if ch == self.current_channel:
            return
        self.msg_entry.delete(0, tkinter.END)
        self.msg_entry.insert(0, f"/join {ch}")
        self.send_message()

    def on_user_double_click(self, event):
        sel = self.user_listbox.curselection()
        if not sel:
            return
        user = self.user_listbox.get(sel[0])
        if user == self.nickname.get():
            return
        self.msg_entry.delete(0, tkinter.END)
        self.msg_entry.insert(0, f"/msg {user} ")
        self.msg_entry.focus()

    # ---------- завершение ----------
    def on_close(self):
        try:
            self.is_connected = False
            if self.server_instance:
                self.server_instance.stop()
            if self.socket:
                try:
                    self.socket.close()
                except Exception:
                    pass
        finally:
            try:
                self.root.destroy()
            except Exception:
                pass


if __name__ == "__main__":
    root = tkinter.Tk()
    app = ChatApp(root)
    root.mainloop()
