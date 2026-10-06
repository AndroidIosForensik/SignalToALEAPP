#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
signal_backup_zu_aleapp.py
==========================
Wandelt ein NEUES lokales Signal-Android-Backup (Ordner "SignalBackups" bzw. die ZIP davon)
in eine Pseudo-Extraktion um, die ALEAPP mit seinem Signal-Parser (scripts/artifacts/signalAndroid.py)
einlesen kann:

    <Ausgabe>/ALEAPP_Signal.zip
        data/data/org.thoughtcrime.securesms/databases/signal.db   (SQLCipher, wie auf dem Gerät)
        data/data/org.thoughtcrime.securesms/app_parts/part*.mms   (Anhänge, AES-CTR wie auf dem Gerät)
        extra/Secrets/secrets.json                                  (DB-Schlüssel + modernKey für ALEAPP)
    <Ausgabe>/report.txt   (Hashwerte, Schlüsselableitung, Statistik, Mapping-Hinweise)
    <Ausgabe>/backup.json  (vollständiger Backup-Inhalt als JSON, auch Felder ohne ALEAPP-Entsprechung)

In ALEAPP dann: Input = ALEAPP_Signal.zip (Typ "zip") oder der entpackte Ordner (Typ "fs").

Benötigt: Python 3.9+   ->   pip install cryptography protobuf
Start:    Doppelklick bzw.  python signal_backup_zu_aleapp.py   (öffnet ein Fenster)
          oder  python signal_backup_zu_aleapp.py <SignalBackups-Ordner|ZIP> "<64 Zeichen>" <Ausgabeordner>
          (EXE:  SignalBackup_zu_ALEAPP.exe <SignalBackups-Ordner|ZIP> "<64 Zeichen>" <Ausgabeordner>)

WICHTIG: Die erzeugte signal.db ist eine REKONSTRUKTION aus dem Backup, keine Originaldatei vom Gerät.
Datenbank- und Anhangschlüssel werden bei jedem Lauf zufällig neu erzeugt und stehen in secrets.json.
"""

# =====================================================================================
#  HIER EINTRAGEN (optional). Leer lassen = das Programm fragt per Fenster nach.
# =====================================================================================
SCHLUESSEL     = ""   # 64-stelliger Wiederherstellungsschlüssel aus Signal (Leerzeichen egal)
BACKUP_ORDNER  = ""   # z.B. r"C:\Users\Mustermann\Downloads\SignalBackups"  oder  r"...\SignalBackups.zip"
AUSGABE_ORDNER = ""   # leer = Ordner "ALEAPP_Signal" neben dem Backup
# =====================================================================================

import argparse, base64, datetime, getpass, gzip, hashlib, hmac, json, os, re, shutil, sqlite3
import struct, sys, tempfile, uuid, zipfile, zlib
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    from cryptography.hazmat.primitives import hashes
    from google.protobuf import descriptor_pb2, descriptor_pool, json_format
    try:
        from google.protobuf.message_factory import GetMessageClass
    except ImportError:
        GetMessageClass = None
        from google.protobuf import message_factory
except ImportError:
    print("Fehlende Pakete. Bitte installieren:\n    pip install cryptography protobuf")
    input("Enter zum Beenden ...") if sys.stdin and sys.stdin.isatty() else None
    sys.exit(1)

PKG = "org.thoughtcrime.securesms"

# Als Fenster-EXE (PyInstaller --windowed) gibt es keine Konsole
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w", encoding="utf-8")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w", encoding="utf-8")
VERSION = "1.1 (2026-09-30)"


class Abbruch(Exception):
    pass


# ------------------------------------------------------------------ Protobuf-Schema (libsignal backup.proto + LocalBackup.proto)
def _load_schema():
    fds = descriptor_pb2.FileDescriptorSet.FromString(zlib.decompress(base64.b64decode(DESCRIPTOR_B64)))
    pool = descriptor_pool.DescriptorPool()
    for f in fds.file:
        pool.Add(f)

    def cls(name):
        d = pool.FindMessageTypeByName(name)
        return GetMessageClass(d) if GetMessageClass else message_factory.MessageFactory(pool).GetPrototype(d)
    return (cls("signal.backup.BackupInfo"), cls("signal.backup.Frame"),
            cls("signal.backup.local.Metadata"), cls("signal.backup.local.FilesFrame"))


# ------------------------------------------------------------------ Krypto: Signal-Backup lesen
def hkdf(ikm, info, length, salt=None):
    prk = hmac.new(salt if salt else b"\x00" * 32, ikm, hashlib.sha256).digest()
    return HKDFExpand(hashes.SHA256(), length, info).derive(prk)


def normalize_aep(s):
    s = (s or "").replace(" ", "").replace("-", "").replace("#", "o").replace("=", "0").strip().lower()
    if not re.fullmatch(r"[a-z0-9]{64}", s):
        raise Abbruch("Der Wiederherstellungsschlüssel muss aus genau 64 Zeichen (a-z, 0-9) bestehen "
                      f"(erhalten: {len(s)}). Der alte 30-stellige Zahlencode gehört zum ALTEN .backup-Format.")
    return s


def aes_ctr(key, nonce16, data):
    d = Cipher(algorithms.AES(key), modes.CTR(nonce16)).decryptor()
    return d.update(data) + d.finalize()


def aes_cbc_dec(key, iv, data, unpad=True):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    out = d.update(data) + d.finalize()
    if unpad:
        p = out[-1]
        if 1 <= p <= 16 and out[-p:] == bytes([p]) * p:
            out = out[:-p]
    return out


def aes_cbc_enc_raw(key, iv, data):
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()


def read_varint(buf, pos):
    shift = result = 0
    while True:
        b = buf[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7


def delimited(buf):
    pos = 0
    while pos < len(buf):
        n, pos = read_varint(buf, pos)
        yield buf[pos:pos + n]
        pos += n


def decrypt_backup(aep, meta_b, main_b):
    backup_key = hkdf(aep.encode(), b"20240801_SIGNAL_BACKUP_KEY", 32)
    meta_key = hkdf(backup_key, b"20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY", 32)
    md = LocalMetadata.FromString(meta_b)
    backup_id = aes_ctr(meta_key, md.backupId.iv + b"\x00" * 4, md.backupId.encryptedId)
    if main_b[:8] == b"SBACKUP\x01":
        raise Abbruch("Das Backup nutzt das Forward-Secrecy-Format (Cloud-Backup) – nicht unterstützt.")
    k = hkdf(backup_key, b"20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:" + backup_id, 64)
    hk, ak = k[:32], k[32:]
    body, tag = main_b[:-32], main_b[-32:]
    if not hmac.compare_digest(hmac.new(hk, body, hashlib.sha256).digest(), tag):
        raise Abbruch("HMAC stimmt nicht – falscher Wiederherstellungsschlüssel oder beschädigtes Backup.")
    raw = gzip.decompress(aes_cbc_dec(ak, body[:16], body[16:]))
    return backup_key, backup_id, md.version, raw


def decrypt_local_attachment(data, local_key):
    ak, hk = local_key[:32], local_key[32:]
    body, tag = data[:-32], data[-32:]
    if len(body) < 32 or not hmac.compare_digest(hmac.new(hk, body, hashlib.sha256).digest(), tag):
        return None
    return aes_cbc_dec(ak, body[:16], body[16:])


# ------------------------------------------------------------------ Krypto: ALEAPP-kompatibel schreiben
PAGE_SIZE, RESERVE = 4096, 48          # SQLCipher: IV(16) + HMAC-SHA1(20), auf 16 aufgerundet


def empty_sqlite_with_reserve(path):
    """Leere SQLite-Datei mit 48 Byte reserviertem Platz je Seite (wie SQLCipher sie braucht)."""
    h = bytearray(PAGE_SIZE)
    h[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", h, 16, PAGE_SIZE)
    h[18] = h[19] = 1
    h[20], h[21], h[22], h[23] = RESERVE, 64, 32, 32
    struct.pack_into(">I", h, 24, 1)
    struct.pack_into(">I", h, 28, 1)
    struct.pack_into(">I", h, 44, 4)
    struct.pack_into(">I", h, 56, 1)
    struct.pack_into(">I", h, 92, 1)
    struct.pack_into(">I", h, 96, 3045000)
    h[100] = 0x0D
    struct.pack_into(">H", h, 105, PAGE_SIZE - RESERVE)
    Path(path).write_bytes(bytes(h))


def sqlcipher_encrypt(plain, passphrase):
    """SQLCipher-Verschlüsselung mit Signals Parametern (PBKDF2-SHA1, 1 Iteration, HMAC-SHA1, 4096er Seiten)."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha1", passphrase.encode(), salt, 1, 32)
    hkey = hashlib.pbkdf2_hmac("sha1", key, bytes(b ^ 0x3A for b in salt), 2, 32)
    out = bytearray()
    for i in range(len(plain) // PAGE_SIZE):
        pg = i + 1
        page = plain[i * PAGE_SIZE:(i + 1) * PAGE_SIZE]
        start = 16 if pg == 1 else 0
        iv = os.urandom(16)
        ct = aes_cbc_enc_raw(key, iv, page[start:PAGE_SIZE - RESERVE])
        mac = hmac.new(hkey, ct + iv + pg.to_bytes(4, "little"), hashlib.sha1).digest()
        out += (salt if pg == 1 else b"") + ct + iv + mac + b"\x00" * (RESERVE - 16 - 20)
    return bytes(out)


def sqlcipher_verify(enc, passphrase, plain):
    salt = enc[:16]
    key = hashlib.pbkdf2_hmac("sha1", passphrase.encode(), salt, 1, 32)
    hkey = hashlib.pbkdf2_hmac("sha1", key, bytes(b ^ 0x3A for b in salt), 2, 32)
    for i in range(len(enc) // PAGE_SIZE):
        pg = i + 1
        page = enc[i * PAGE_SIZE:(i + 1) * PAGE_SIZE]
        s = 16 if pg == 1 else 0
        e = PAGE_SIZE - RESERVE
        iv, mac = page[e:e + 16], page[e + 16:e + 36]
        if not hmac.compare_digest(hmac.new(hkey, page[s:e + 16] + pg.to_bytes(4, "little"), hashlib.sha1).digest(), mac):
            return False
        body = aes_cbc_dec(key, iv, page[s:e], unpad=False)
        ref = plain[i * PAGE_SIZE:(i + 1) * PAGE_SIZE]
        if body != ref[s:e]:
            return False
    return True


def signal_attachment_encrypt(modern_key, data_random, plain):
    """Wie Signal-Android (und ALEAPP _decrypt_attachment): AES-256-CTR, Key = HMAC-SHA256(modernKey, data_random)."""
    key = hmac.new(modern_key, data_random, hashlib.sha256).digest()
    e = Cipher(algorithms.AES(key), modes.CTR(b"\x00" * 16)).encryptor()
    return e.update(plain) + e.finalize()


# ------------------------------------------------------------------ Signal-DB-Schema (Teilmenge, Spaltennamen wie Signal-Android)
SCHEMA = """
CREATE TABLE recipient (_id INTEGER PRIMARY KEY, type INTEGER DEFAULT 0, e164 TEXT, username TEXT,
  aci TEXT, pni TEXT, group_id TEXT, profile_given_name TEXT, profile_family_name TEXT,
  profile_joined_name TEXT, system_given_name TEXT, system_family_name TEXT, system_joined_name TEXT,
  nickname_given_name TEXT, nickname_family_name TEXT, nickname_joined_name TEXT,
  registered INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0, hidden INTEGER DEFAULT 0,
  about TEXT, about_emoji TEXT, note TEXT, last_profile_fetch INTEGER DEFAULT 0,
  profile_sharing INTEGER DEFAULT 0, profile_key TEXT, identity_key TEXT, backup_source TEXT);
CREATE TABLE thread (_id INTEGER PRIMARY KEY, recipient_id INTEGER, date INTEGER DEFAULT 0,
  meaningful_messages INTEGER DEFAULT 0, archived INTEGER DEFAULT 0, pinned_order INTEGER,
  expires_in INTEGER DEFAULT 0, active INTEGER DEFAULT 1);
CREATE TABLE message (_id INTEGER PRIMARY KEY AUTOINCREMENT, date_sent INTEGER NOT NULL,
  date_received INTEGER NOT NULL, date_server INTEGER DEFAULT -1, thread_id INTEGER NOT NULL,
  from_recipient_id INTEGER NOT NULL, from_device_id INTEGER, to_recipient_id INTEGER NOT NULL,
  type INTEGER NOT NULL, body TEXT, read INTEGER DEFAULT 0, expires_in INTEGER DEFAULT 0,
  expire_started INTEGER DEFAULT 0, remote_deleted INTEGER DEFAULT 0, view_once INTEGER DEFAULT 0,
  quote_id INTEGER DEFAULT 0, quote_author INTEGER DEFAULT 0, quote_body TEXT,
  quote_missing INTEGER DEFAULT 0, quote_type INTEGER DEFAULT 0, unidentified INTEGER DEFAULT 0,
  latest_revision_id INTEGER DEFAULT NULL, original_message_id INTEGER DEFAULT NULL,
  revision_number INTEGER DEFAULT 0, pinned_at INTEGER DEFAULT 0, backup_item_type TEXT);
CREATE TABLE attachment (_id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER,
  content_type TEXT, remote_key TEXT, remote_location TEXT, cdn_number INTEGER,
  transfer_state INTEGER, data_file TEXT, data_size INTEGER, data_random BLOB, file_name TEXT,
  fast_preflight_id TEXT, voice_note INTEGER DEFAULT 0, borderless INTEGER DEFAULT 0,
  video_gif INTEGER DEFAULT 0, quote INTEGER DEFAULT 0, width INTEGER DEFAULT 0,
  height INTEGER DEFAULT 0, caption TEXT, sticker_pack_id TEXT, sticker_pack_key TEXT,
  sticker_id INTEGER DEFAULT -1, sticker_emoji TEXT, blur_hash TEXT, upload_timestamp INTEGER DEFAULT 0,
  display_order INTEGER DEFAULT 0, thumbnail_file TEXT, thumbnail_random BLOB,
  data_hash_end TEXT, backup_media_name TEXT);
CREATE TABLE reaction (_id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL, author_id INTEGER NOT NULL,
  emoji TEXT NOT NULL, date_sent INTEGER NOT NULL, date_received INTEGER NOT NULL);
CREATE TABLE groups (_id INTEGER PRIMARY KEY, group_id TEXT, recipient_id INTEGER, title TEXT,
  avatar_id INTEGER DEFAULT 0, timestamp INTEGER, active INTEGER DEFAULT 1, mms INTEGER DEFAULT 0,
  master_key BLOB, revision INTEGER, decrypted_group BLOB, expected_v2_id TEXT,
  unmigrated_v1_members TEXT, distribution_id TEXT, show_as_story_state INTEGER DEFAULT 0,
  last_force_update_timestamp INTEGER DEFAULT 0, description TEXT);
CREATE TABLE group_membership (_id INTEGER PRIMARY KEY, group_id TEXT NOT NULL,
  recipient_id INTEGER NOT NULL, endorsement BLOB, role INTEGER DEFAULT 0);
CREATE TABLE call (_id INTEGER PRIMARY KEY, call_id INTEGER NOT NULL, message_id INTEGER,
  peer INTEGER NOT NULL, call_link INTEGER, type INTEGER NOT NULL, direction INTEGER NOT NULL,
  event INTEGER NOT NULL, timestamp INTEGER NOT NULL, ringer INTEGER DEFAULT NULL,
  deletion_timestamp INTEGER DEFAULT 0, parent_call INTEGER, read INTEGER DEFAULT 1,
  local_joined INTEGER DEFAULT 0, group_call_active INTEGER DEFAULT 0);
CREATE TABLE backup_conversion_info (key TEXT PRIMARY KEY, value TEXT);
"""

# MessageTypes.java: BASE_INBOX_TYPE=20, BASE_SENT_TYPE=23, BASE_SENT_FAILED_TYPE=24, BASE_SENDING_TYPE=22
# + PUSH_MESSAGE_BIT (0x200000) + SECURE_MESSAGE_BIT (0x800000)
T_SECURE = 0x800000 | 0x200000
T_IN, T_SENT, T_SENDING, T_FAILED = 20 | T_SECURE, 23 | T_SECURE, 22 | T_SECURE, 24 | T_SECURE
T_DIRECTIONLESS = 0 | T_SECURE        # ALEAPP zeigt "Unknown" -> Systemmeldungen

CALL_EVENT_INDIVIDUAL = {0: 1, 1: 1, 2: 2, 3: 3, 4: 10}           # State -> ALEAPP CALL_EVENTS
CALL_EVENT_GROUP = {0: 5, 1: 5, 2: 6, 3: 7, 4: 1, 5: 8, 6: 3, 7: 10, 8: 9}

SIMPLE_UPDATE_DE = {
    1: "ist Signal beigetreten", 2: "Sicherheitsnummer hat sich geändert", 3: "als verifiziert markiert",
    4: "als nicht verifiziert markiert", 5: "hat die Telefonnummer geändert", 6: "Spendenaufruf (Release Notes)",
    7: "Sitzung beendet", 8: "Chat-Sitzung erneuert", 9: "Nachricht konnte nicht entschlüsselt werden",
    10: "Zahlungen aktiviert", 11: "Anfrage zur Aktivierung von Zahlungen", 12: "nicht unterstützte Nachricht",
    13: "als Spam gemeldet", 14: "blockiert", 15: "Blockierung aufgehoben", 16: "Nachrichtenanfrage angenommen",
}


def uuid_str(b):
    return str(uuid.UUID(bytes=bytes(b))) if b and len(b) == 16 else None


def joined(*parts):
    s = " ".join(p for p in parts if p).strip()
    return s or None


# ------------------------------------------------------------------ Konvertierung
def convert(backup_path, aep_input, out_dir, log=print):
    aep = normalize_aep(aep_input)
    backup_path = Path(backup_path).expanduser()
    tmp = Path(tempfile.mkdtemp(prefix="signal2aleapp_"))
    try:
        # --- Eingabe finden (Ordner oder ZIP)
        if backup_path.is_file() and backup_path.suffix.lower() == ".zip":
            log(f"Entpacke {backup_path.name} ...")
            with zipfile.ZipFile(backup_path) as z:
                z.extractall(tmp / "in")
            search_root = tmp / "in"
        elif backup_path.is_dir():
            search_root = backup_path
        else:
            raise Abbruch(f"Backup nicht gefunden: {backup_path}")
        snaps = sorted({p.parent for p in search_root.rglob("metadata")
                        if p.parent.name.startswith("signal-backup-") and (p.parent / "main").exists()},
                       key=lambda p: p.name)
        if not snaps:
            raise Abbruch("Kein Unterordner 'signal-backup-JJJJ-MM-TT-...' mit 'metadata' und 'main' gefunden.")
        snap = snaps[-1]
        root = snap.parent
        if len(snaps) > 1:
            log("Mehrere Snapshots gefunden: " + ", ".join(p.name for p in snaps) + f" -> verwende den neuesten: {snap.name}")
        else:
            log(f"Snapshot: {snap.name}")

        meta_b, main_b = (snap / "metadata").read_bytes(), (snap / "main").read_bytes()
        backup_key, backup_id, md_version, raw = decrypt_backup(aep, meta_b, main_b)
        log("Backup entschlüsselt (HMAC ok).")

        frames = list(delimited(raw))
        info = BackupInfo.FromString(frames[0])
        parsed = [Frame.FromString(f) for f in frames[1:]]
        log(f"{len(parsed)} Frames gelesen.")

        on_disk = {}
        if (root / "files").is_dir():
            on_disk = {p.name: p for p in (root / "files").rglob("*") if p.is_file()}
        manifest = [FilesFrame.FromString(f).mediaName for f in delimited((snap / "files").read_bytes())] \
            if (snap / "files").exists() else []

        # --- Ausgabe vorbereiten
        out_dir = Path(out_dir).expanduser().resolve()
        stage = out_dir / "ALEAPP_Signal"
        if stage.exists():
            shutil.rmtree(stage)
        app = stage / "data" / "data" / PKG
        (app / "databases").mkdir(parents=True)
        (app / "app_parts").mkdir(parents=True)
        (stage / "extra" / "Secrets").mkdir(parents=True)

        db_key_hex = os.urandom(32).hex()
        modern_key = os.urandom(32)

        plain_path = tmp / "signal_plain.db"
        empty_sqlite_with_reserve(plain_path)
        db = sqlite3.connect(plain_path)
        db.executescript(SCHEMA)

        # --- Stammdaten
        account = next((f.account for f in parsed if f.WhichOneof("item") == "account"), None)
        recipients = {f.recipient.id: f.recipient for f in parsed if f.WhichOneof("item") == "recipient"}
        chats = {f.chat.id: f.chat for f in parsed if f.WhichOneof("item") == "chat"}
        self_id = next((rid for rid, r in recipients.items() if r.WhichOneof("destination") == "self"), None)
        aci_to_rid = {}
        for rid, r in recipients.items():
            if r.WhichOneof("destination") == "contact" and r.contact.aci:
                aci_to_rid[bytes(r.contact.aci)] = rid

        # Eigene ACI bestimmen: BackupId = HKDF(BackupKey, "20241024_SIGNAL_BACKUP_ID:" || ACI) -> Kandidaten prüfen
        own_aci = None
        cand = set()
        for r in recipients.values():
            if r.WhichOneof("destination") == "group":
                for m in r.group.snapshot.members:
                    cand.add(bytes(m.userId))
        for c in cand:
            if len(c) == 16 and hkdf(backup_key, b"20241024_SIGNAL_BACKUP_ID:" + c, 16) == backup_id:
                own_aci = c
                break
        if own_aci and self_id is not None:
            aci_to_rid[own_aci] = self_id

        for rid, r in recipients.items():
            kind = r.WhichOneof("destination")
            row = dict(_id=rid, type=0, backup_source=kind)
            if kind == "contact":
                c = r.contact
                row.update(
                    e164=f"+{c.e164}" if c.e164 else None, username=c.username or None,
                    aci=uuid_str(c.aci), pni=("PNI:" + uuid_str(c.pni)) if uuid_str(c.pni) else None,
                    profile_given_name=c.profileGivenName or None, profile_family_name=c.profileFamilyName or None,
                    profile_joined_name=joined(c.profileGivenName, c.profileFamilyName),
                    system_given_name=c.systemGivenName or None, system_family_name=c.systemFamilyName or None,
                    system_joined_name=joined(c.systemGivenName, c.systemFamilyName) or (c.systemNickname or None),
                    nickname_given_name=c.nickname.given or None, nickname_family_name=c.nickname.family or None,
                    nickname_joined_name=joined(c.nickname.given, c.nickname.family),
                    registered=1 if c.WhichOneof("registration") == "registered" else 2,
                    blocked=int(c.blocked), hidden=int(c.visibility != 0), note=c.note or None,
                    profile_sharing=int(c.profileSharing),
                    profile_key=base64.b64encode(c.profileKey).decode() if c.profileKey else None,
                    identity_key=base64.b64encode(c.identityKey).decode() if c.identityKey else None)
            elif kind == "self":
                row.update(profile_given_name=(account.givenName if account else None) or None,
                           profile_family_name=(account.familyName if account else None) or None,
                           profile_joined_name=joined(account.givenName, account.familyName) if account else None,
                           username=(account.username if account else None) or None,
                           about=(account.bioText if account else None) or None,
                           about_emoji=(account.bioEmoji if account else None) or None,
                           aci=uuid_str(own_aci), registered=1)
                if not row["profile_joined_name"]:
                    row["profile_joined_name"] = "Ich (Geräteinhaber)"
            elif kind == "group":
                row.update(type=2, group_id="masterKey:" + bytes(r.group.masterKey).hex(),
                           profile_joined_name=r.group.snapshot.title.title or None,
                           system_joined_name=r.group.snapshot.title.title or None, blocked=int(r.group.blocked))
            elif kind == "distributionList":
                row.update(type=3, profile_joined_name=r.distributionList.distributionList.name or "Story-Liste"
                           if r.distributionList.HasField("distributionList") else "Story-Liste (gelöscht)")
            elif kind == "callLink":
                row.update(type=4, profile_joined_name=r.callLink.name or "Anruf-Link")
            elif kind == "releaseNotes":
                row.update(profile_joined_name="Signal (Release Notes)")
            cols = ",".join(row)
            db.execute(f"INSERT INTO recipient ({cols}) VALUES ({','.join('?' * len(row))})", list(row.values()))

        # Gruppen + Mitglieder
        for rid, r in recipients.items():
            if r.WhichOneof("destination") != "group":
                continue
            g = r.group
            gid = "masterKey:" + bytes(g.masterKey).hex()
            db.execute("INSERT INTO groups (group_id, recipient_id, title, active, mms, master_key, revision, description) "
                       "VALUES (?,?,?,?,?,?,?,?)",
                       (gid, rid, g.snapshot.title.title or None, 1, 0, bytes(g.masterKey), g.snapshot.version,
                        g.snapshot.description.descriptionText or None))
            for m in g.snapshot.members:
                mid = aci_to_rid.get(bytes(m.userId))
                if mid is None:  # Mitglied ohne eigenen Kontakt-Frame -> Platzhalter-Empfänger anlegen
                    mid = db.execute("SELECT COALESCE(MAX(_id),0)+1 FROM recipient").fetchone()[0]
                    db.execute("INSERT INTO recipient (_id, type, aci, profile_joined_name, backup_source) VALUES (?,?,?,?,?)",
                               (mid, 0, uuid_str(m.userId), f"Unbekannt ({uuid_str(m.userId)})", "group_member_only"))
                    aci_to_rid[bytes(m.userId)] = mid
                db.execute("INSERT INTO group_membership (group_id, recipient_id, role) VALUES (?,?,?)", (gid, mid, m.role))

        # Threads
        for cid, c in chats.items():
            db.execute("INSERT INTO thread (_id, recipient_id, archived, pinned_order, expires_in) VALUES (?,?,?,?,?)",
                       (cid, c.recipientId, int(c.archived), c.pinnedOrder if c.HasField("pinnedOrder") else None,
                        c.expirationTimerMs))

        # --- Anhänge vorbereiten
        used_files, att_stats = set(), {"ok": 0, "fehlt": 0, "ohne_lokal": 0}

        def load_attachment(fp):
            li = fp.locatorInfo
            if not li.localKey:
                att_stats["ohne_lokal"] += 1
                return None
            names = []
            if li.plaintextHash:
                names.append(hashlib.sha256(li.plaintextHash + li.localKey).hexdigest())
            for nm in names:
                if nm in on_disk:
                    p = decrypt_local_attachment(on_disk[nm].read_bytes(), li.localKey)
                    if p is not None:
                        used_files.add(nm)
                        return p[:li.size] if li.size and len(p) >= li.size else p
            for nm, path in on_disk.items():          # Fallback: passende Datei über HMAC suchen
                if nm in used_files:
                    continue
                p = decrypt_local_attachment(path.read_bytes(), li.localKey)
                if p is not None:
                    used_files.add(nm)
                    return p[:li.size] if li.size and len(p) >= li.size else p
            att_stats["fehlt"] += 1
            return None

        def add_attachment(msg_id, fp, flag=0, order=0, sticker=None):
            plain = load_attachment(fp)
            data_file = data_random = None
            size = fp.locatorInfo.size
            if plain is not None:
                data_random = os.urandom(32)
                fname = f"part{int.from_bytes(os.urandom(8), 'big')}.mms"
                (app / "app_parts" / fname).write_bytes(signal_attachment_encrypt(modern_key, data_random, plain))
                data_file = f"/data/user/0/{PKG}/app_parts/{fname}"
                size = len(plain)
                att_stats["ok"] += 1
            db.execute(
                "INSERT INTO attachment (message_id, content_type, transfer_state, data_file, data_size, data_random, "
                "file_name, voice_note, borderless, video_gif, width, height, caption, blur_hash, upload_timestamp, "
                "display_order, sticker_pack_id, sticker_pack_key, sticker_id, sticker_emoji, remote_key, cdn_number, "
                "remote_location, data_hash_end) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (msg_id, fp.contentType or None, 0 if plain is not None else 2, data_file, size, data_random,
                 fp.fileName or None, int(flag == 1), int(flag == 2), int(flag == 3), fp.width, fp.height,
                 fp.caption or None, fp.blurHash or None, fp.locatorInfo.transitTierUploadTimestamp or 0, order,
                 sticker[0] if sticker else None, sticker[1] if sticker else None,
                 sticker[2] if sticker else -1, sticker[3] if sticker else None,
                 base64.b64encode(fp.locatorInfo.key).decode() if fp.locatorInfo.key else None,
                 fp.locatorInfo.transitCdnNumber if fp.locatorInfo.HasField("transitCdnNumber") else None,
                 fp.locatorInfo.transitCdnKey or None,
                 base64.b64encode(fp.locatorInfo.plaintextHash).decode() if fp.locatorInfo.plaintextHash else None))
            return plain

        # --- Nachrichten
        name_of = lambda rid: (db.execute("SELECT COALESCE(nickname_joined_name, system_joined_name, profile_joined_name, "
                                          "e164, username, '#'||_id) FROM recipient WHERE _id=?", (rid,)).fetchone() or [f"#{rid}"])[0]
        sent_ts = set()
        for f in parsed:
            if f.WhichOneof("item") == "chatItem":
                sent_ts.add(f.chatItem.dateSent)
        counts = {"messages": 0, "revisions": 0, "reactions": 0, "calls": 0}
        thread_last = {}

        def describe_update(ci):
            u = ci.updateMessage
            k = u.WhichOneof("update")
            who = name_of(ci.authorId)
            if k == "simpleUpdate":
                return f"[System] {who}: {SIMPLE_UPDATE_DE.get(u.simpleUpdate.type, 'Systemmeldung')}"
            if k == "expirationTimerChange":
                ms = u.expirationTimerChange.expiresInMs
                return f"[System] {who}: verschwindende Nachrichten " + (f"auf {ms // 1000} s gesetzt" if ms else "deaktiviert")
            if k == "profileChange":
                return f"[System] Profilname geändert: '{u.profileChange.previousName}' -> '{u.profileChange.newName}'"
            if k == "individualCall":
                c = u.individualCall
                return "[Anruf] " + ("Video" if c.type == 2 else "Audio") + ("anruf ausgehend" if c.direction == 2 else "anruf eingehend") \
                    + {2: " (nicht angenommen)", 3: " (verpasst)", 4: " (verpasst, Benachrichtigungsprofil)"}.get(c.state, "")
            if k == "groupCall":
                return "[Anruf] Gruppenanruf"
            if k == "groupChange":
                kinds = [x.WhichOneof("update") for x in u.groupChange.updates]
                return "[Gruppe] " + ", ".join(kinds)
            if k == "threadMerge":
                return "[System] Chats zusammengeführt"
            if k == "sessionSwitchover":
                return "[System] Sitzungswechsel"
            if k == "learnedProfileChange":
                return "[System] Profilname erkannt"
            if k == "pinMessage":
                return "[System] Nachricht angeheftet"
            if k == "pollTerminate":
                return "[System] Umfrage beendet"
            return f"[System] {k or 'unbekannt'}"

        def insert_item(ci, chat, latest_id=None, original_id=None, rev_no=0, is_revision=False):
            kind = ci.WhichOneof("item")
            d = ci.WhichOneof("directionalDetails")
            peer = chat.recipientId if chat else 0
            if d == "incoming":
                typ, frm, to = T_IN, ci.authorId, self_id or 0
                date_rcv, date_srv, read = ci.incoming.dateReceived, ci.incoming.dateServerSent or -1, int(ci.incoming.read)
                unident = int(ci.incoming.sealedSender)
            elif d == "outgoing":
                st = [s.WhichOneof("deliveryStatus") for s in ci.outgoing.sendStatus]
                typ = T_FAILED if "failed" in st else (T_SENDING if st and all(s == "pending" for s in st) else T_SENT)
                frm, to = ci.authorId, peer
                date_rcv, date_srv, read, unident = ci.outgoing.dateReceived or ci.dateSent, -1, 1, 0
            else:
                typ, frm = T_DIRECTIONLESS, ci.authorId
                to = peer if ci.authorId == self_id else (self_id or peer)
                date_rcv, date_srv, read, unident = ci.dateSent, -1, 1, 0

            body, remote_deleted, view_once = None, 0, 0
            quote = (0, 0, None, 0, 0)
            reactions, atts = [], []
            if kind == "standardMessage":
                sm = ci.standardMessage
                body = sm.text.body or None
                if sm.HasField("quote"):
                    q = sm.quote
                    tgt = q.targetSentTimestamp if q.HasField("targetSentTimestamp") else 0
                    quote = (tgt, q.authorId, q.text.body or None, int(not tgt or tgt not in sent_ts), q.type)
                for i, a in enumerate(sm.attachments):
                    atts.append((a.pointer, a.flag, i, None))
                reactions = sm.reactions
                if sm.linkPreview:
                    body = (body or "") + "".join(f"\n[Link-Vorschau] {lp.url} {lp.title}".rstrip() for lp in sm.linkPreview)
            elif kind == "stickerMessage":
                s = ci.stickerMessage.sticker
                body = f"[Sticker] {s.emoji}".strip()
                if s.HasField("data"):
                    atts.append((s.data, 2, 0, (s.packId.hex(), s.packKey.hex(), s.stickerId, s.emoji or None)))
                reactions = ci.stickerMessage.reactions
            elif kind == "viewOnceMessage":
                view_once = 1
                if ci.viewOnceMessage.HasField("attachment"):
                    atts.append((ci.viewOnceMessage.attachment.pointer, ci.viewOnceMessage.attachment.flag, 0, None))
                reactions = ci.viewOnceMessage.reactions
            elif kind in ("remoteDeletedMessage", "adminDeletedMessage"):
                remote_deleted = 1
            elif kind == "contactMessage":
                c = ci.contactMessage.contact
                nums = ", ".join(p.value for p in c.number)
                body = f"[Kontakt] {joined(c.name.givenName, c.name.familyName) or c.name.nickname} {nums}".strip()
                if c.HasField("avatar"):
                    atts.append((c.avatar, 0, 0, None))
                reactions = ci.contactMessage.reactions
            elif kind == "poll":
                p = ci.poll
                body = f"[Umfrage] {p.question} | " + " | ".join(
                    f"{o.option}: " + (", ".join(name_of(v.voterId) for v in o.votes) or "–") for o in p.options)
                reactions = p.reactions
            elif kind == "updateMessage":
                body = describe_update(ci)
            elif kind == "paymentNotification":
                pn = ci.paymentNotification
                body = f"[Zahlung] {pn.amountMob} MOB {pn.note}".strip()
            elif kind == "giftBadge":
                body = "[Geschenk-Abzeichen]"
            elif kind == "directStoryReplyMessage":
                r = ci.directStoryReplyMessage
                body = "[Story-Antwort] " + (r.textReply.text.body if r.HasField("textReply") else r.emoji)
                reactions = r.reactions
            else:
                body = f"[{kind or 'unbekannt'}]"

            if is_revision:
                body = "[frühere Fassung – bearbeitet] " + (body or "")
            cur = db.execute(
                "INSERT INTO message (date_sent, date_received, date_server, thread_id, from_recipient_id, "
                "to_recipient_id, type, body, read, expires_in, expire_started, remote_deleted, view_once, quote_id, "
                "quote_author, quote_body, quote_missing, quote_type, unidentified, latest_revision_id, "
                "original_message_id, revision_number, pinned_at, backup_item_type) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ci.dateSent, date_rcv, date_srv, ci.chatId, frm, to, typ, body, read, ci.expiresInMs,
                 ci.expireStartDate, remote_deleted, view_once, *quote, unident, latest_id, original_id, rev_no,
                 ci.pinDetails.pinnedAtTimestamp if ci.HasField("pinDetails") else 0, kind))
            mid = cur.lastrowid
            for fp, flag, order, sticker in atts:
                add_attachment(mid, fp, flag, order, sticker)
            for r in reactions:
                db.execute("INSERT INTO reaction (message_id, author_id, emoji, date_sent, date_received) VALUES (?,?,?,?,?)",
                           (mid, r.authorId, r.emoji, r.sentTimestamp, r.sentTimestamp))
                counts["reactions"] += 1
            if kind == "updateMessage":
                u = ci.updateMessage
                if u.WhichOneof("update") == "individualCall":
                    c = u.individualCall
                    db.execute("INSERT INTO call (call_id, message_id, peer, type, direction, event, timestamp, read) "
                               "VALUES (?,?,?,?,?,?,?,?)",
                               (c.callId or 0, mid, peer, 1 if c.type == 2 else 0, 1 if c.direction == 2 else 0,
                                CALL_EVENT_INDIVIDUAL.get(c.state, 1), c.startedCallTimestamp or ci.dateSent, int(c.read)))
                    counts["calls"] += 1
                elif u.WhichOneof("update") == "groupCall":
                    c = u.groupCall
                    outgoing = self_id is not None and self_id in (c.ringerRecipientId, c.startedCallRecipientId)
                    db.execute("INSERT INTO call (call_id, message_id, peer, type, direction, event, timestamp, ringer, read) "
                               "VALUES (?,?,?,?,?,?,?,?,?)",
                               (c.callId or 0, mid, peer, 3, int(outgoing), CALL_EVENT_GROUP.get(c.state, 5),
                                c.startedCallTimestamp or ci.dateSent,
                                c.ringerRecipientId if c.HasField("ringerRecipientId") else None, int(c.read)))
                    counts["calls"] += 1
            return mid

        for f in parsed:
            if f.WhichOneof("item") != "chatItem":
                continue
            ci = f.chatItem
            chat = chats.get(ci.chatId)
            if ci.revisions:        # ältere Fassungen bearbeiteter Nachrichten (wie Signal: eigene Zeilen)
                rev_ids = []
                for n, rv in enumerate(ci.revisions):
                    rev_ids.append(insert_item(rv, chat, original_id=rev_ids[0] if rev_ids else None, rev_no=n, is_revision=True))
                    counts["revisions"] += 1
                mid = insert_item(ci, chat, original_id=rev_ids[0], rev_no=len(rev_ids))
                db.execute(f"UPDATE message SET latest_revision_id=? WHERE _id IN ({','.join('?' * len(rev_ids))})", [mid] + rev_ids)
            else:
                insert_item(ci, chat)
            counts["messages"] += 1
            thread_last[ci.chatId] = max(thread_last.get(ci.chatId, 0), ci.dateSent)
        for tid, d in thread_last.items():
            db.execute("UPDATE thread SET date=?, meaningful_messages=1 WHERE _id=?", (d, tid))

        conv_info = {
            "hinweis": "Rekonstruiert aus lokalem Signal-Backup, NICHT die Original-signal.db des Geräts",
            "tool": f"signal_backup_zu_aleapp.py {VERSION}",
            "konvertiert_am_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "snapshot": snap.name,
            "backup_time_ms": str(info.backupTimeMs),
            "app_version": info.currentAppVersion,
            "sha256_main": hashlib.sha256(main_b).hexdigest(),
            "sha256_metadata": hashlib.sha256(meta_b).hexdigest(),
            "backup_id": backup_id.hex(),
            "own_aci": uuid_str(own_aci) or "",
        }
        db.executemany("INSERT INTO backup_conversion_info VALUES (?,?)", conv_info.items())
        db.commit()
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise Abbruch("Interner Fehler: SQLite-Integritätsprüfung fehlgeschlagen.")
        db.execute("VACUUM")
        db.close()

        # --- SQLCipher-verschlüsseln + gegenprüfen
        plain = plain_path.read_bytes()
        if plain[20] != RESERVE or len(plain) % PAGE_SIZE:
            raise Abbruch("Interner Fehler: unerwartetes Seitenlayout der Datenbank.")
        enc = sqlcipher_encrypt(plain, db_key_hex)
        if not sqlcipher_verify(enc, db_key_hex, plain):
            raise Abbruch("Interner Fehler: SQLCipher-Gegenprüfung fehlgeschlagen.")
        (app / "databases" / "signal.db").write_bytes(enc)
        log(f"signal.db erzeugt ({len(enc) // PAGE_SIZE} Seiten, SQLCipher-Gegenprüfung ok).")

        secrets = [{
            "app": PKG,
            "comment": "Erzeugt von signal_backup_zu_aleapp.py aus einem lokalen Signal-Backup – Schlüssel sind zufällig "
                       "generiert und gehören NICHT zum Originalgerät.",
            "script_output": [{"payload": {
                "sqlite db key": db_key_hex,
                "signal attachment key": {"modernKey": base64.b64encode(modern_key).decode()},
            }}],
        }]
        (stage / "extra" / "Secrets" / "secrets.json").write_text(json.dumps(secrets, indent=2), encoding="utf-8")

        # --- ZIP für ALEAPP
        zip_path = out_dir / "ALEAPP_Signal.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for p in sorted(stage.rglob("*")):
                if p.is_file():
                    z.write(p, p.relative_to(stage).as_posix())

        # --- JSON + Report
        with open(out_dir / "backup.json", "w", encoding="utf-8") as fh:
            json.dump({"backupInfo": json_format.MessageToDict(info),
                       "frames": [json_format.MessageToDict(f) for f in parsed]}, fh, ensure_ascii=False, indent=1)
        frame_counts = {}
        for f in parsed:
            frame_counts[f.WhichOneof("item")] = frame_counts.get(f.WhichOneof("item"), 0) + 1
        unused = sorted(set(on_disk) - used_files)
        ts = datetime.datetime.fromtimestamp(info.backupTimeMs / 1000).strftime("%d.%m.%Y %H:%M:%S") if info.backupTimeMs else "?"
        rep = [
            "Signal-Backup -> ALEAPP  |  Konvertierungsbericht",
            "=" * 60,
            f"Tool:                 signal_backup_zu_aleapp.py {VERSION}",
            f"Konvertiert (UTC):    {conv_info['konvertiert_am_utc']}",
            f"Quelle:               {backup_path}",
            f"Snapshot:             {snap.name}",
            f"Backup-Zeitpunkt:     {ts} (lokale Zeit dieses Rechners)",
            f"Signal-Version:       {info.currentAppVersion} (erste Version: {info.firstAppVersion})",
            f"SHA-256 main:         {conv_info['sha256_main']}",
            f"SHA-256 metadata:     {conv_info['sha256_metadata']}",
            f"Metadata-Version:     {md_version}",
            f"BackupId:             {backup_id.hex()}",
            f"Eigene ACI:           {uuid_str(own_aci) or 'nicht bestimmbar (kein Gruppenmitglied passte zur BackupId)'}",
            "",
            f"Frames:               {frame_counts}",
            f"Nachrichten:          {counts['messages']} (+ {counts['revisions']} ältere Fassungen bearbeiteter Nachrichten)",
            f"Reaktionen:           {counts['reactions']}",
            f"Anrufe (call-Tabelle):{counts['calls']}",
            f"Mediendateien:        Manifest {len(manifest)}, auf Datenträger {len(on_disk)}",
            f"Anhänge:              {att_stats['ok']} übernommen, {att_stats['fehlt']} Datei fehlt, "
            f"{att_stats['ohne_lokal']} nicht lokal gesichert (nur Metadaten)",
            f"Nicht zugeordnete Mediendateien: {len(unused)}"
            + (" – Schlüssel nicht im Backup (Signal sichert alle lokal gespeicherten Anhänge, auch solche aus "
               "nicht exportierten Nachrichten, z.B. verschwindende Nachrichten/Stories); nicht entschlüsselbar" if unused else ""),
            *[f"    {u}  ({(on_disk[u].stat().st_size)} Byte)" for u in unused],
            "",
            "Ausgabe:",
            f"  {zip_path}",
            f"  SHA-256 ALEAPP_Signal.zip: {hashlib.sha256(zip_path.read_bytes()).hexdigest()}",
            f"  SHA-256 signal.db:         {hashlib.sha256(enc).hexdigest()}",
            "",
            "Hinweise zur Auswertung:",
            "  * signal.db ist eine Rekonstruktion aus dem Backup (Tabellen/Spalten wie Signal-Android), keine Gerätedatei.",
            "  * DB-Schlüssel und modernKey in extra/Secrets/secrets.json sind bei jedem Lauf neu und zufällig.",
            "  * Texte in [eckigen Klammern] (Sticker, Umfrage, Kontakt, Systemmeldung, Anruf) erzeugt der Konverter.",
            "  * Systemmeldungen haben keinen Richtungstyp -> ALEAPP zeigt Direction 'Unknown'.",
            "  * Bearbeitete Nachrichten: ältere Fassungen sind eigene Zeilen mit Präfix '[frühere Fassung – bearbeitet]'.",
            "  * Gruppen-IDs: 'masterKey:<hex>' – die echte Signal-GroupId wäre nur per zkgroup ableitbar.",
            "  * Gruppenerstellungszeit ist im Backup nicht enthalten (ALEAPP: 'Created Timestamp' leer).",
            "  * Anrufe stammen aus den Anruf-Systemmeldungen der Chats; eine separate Anrufliste enthält das Backup nicht.",
            "  * Nicht gesicherte Inhalte (z.B. Story-Inhalte, gelöschte Nachrichten) kann auch dieser Weg nicht liefern.",
            "  * Alle Felder ohne ALEAPP-Entsprechung stehen vollständig in backup.json.",
        ]
        (out_dir / "report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")
        for line in rep[2:rep.index("Hinweise zur Auswertung:") - 1]:
            log(line)
        log(f"\nFERTIG. In ALEAPP als Eingabe wählen:\n  {zip_path}")
        return zip_path
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ Oberfläche
def run_gui():
    import threading
    import tkinter as tk
    from tkinter import filedialog, scrolledtext, messagebox

    w = tk.Tk()
    w.title("Signal-Backup -> ALEAPP")
    w.geometry("760x520")
    frm = tk.Frame(w, padx=10, pady=10)
    frm.pack(fill="both", expand=True)

    v_src, v_key, v_out = tk.StringVar(value=BACKUP_ORDNER), tk.StringVar(value=SCHLUESSEL), tk.StringVar(value=AUSGABE_ORDNER)

    def row(r, label, var, btn=None, show=None):
        tk.Label(frm, text=label, anchor="w").grid(row=r, column=0, sticky="w", pady=4)
        e = tk.Entry(frm, textvariable=var, width=70, show=show)
        e.grid(row=r, column=1, sticky="we", padx=6)
        if btn:
            tk.Button(frm, text=btn[0], command=btn[1]).grid(row=r, column=2, sticky="we")
        return e

    def pick_dir():
        p = filedialog.askdirectory(title="Ordner SignalBackups wählen")
        if p:
            v_src.set(p)
            if not v_out.get():
                v_out.set(str(Path(p).parent / "ALEAPP_Signal_Export"))

    def pick_zip():
        p = filedialog.askopenfilename(title="SignalBackups.zip wählen", filetypes=[("ZIP", "*.zip"), ("Alle", "*.*")])
        if p:
            v_src.set(p)
            if not v_out.get():
                v_out.set(str(Path(p).parent / "ALEAPP_Signal_Export"))

    def pick_out():
        p = filedialog.askdirectory(title="Ausgabeordner wählen")
        if p:
            v_out.set(p)

    row(0, "Backup (Ordner/ZIP):", v_src, ("Ordner …", pick_dir))
    tk.Button(frm, text="ZIP …", command=pick_zip).grid(row=1, column=2, sticky="we")
    key_entry = row(2, "Wiederherstellungs-\nschlüssel (64 Zeichen):", v_key, show="•")
    v_show = tk.BooleanVar(value=False)
    tk.Checkbutton(frm, text="anzeigen", variable=v_show,
                   command=lambda: key_entry.config(show="" if v_show.get() else "•")).grid(row=3, column=1, sticky="w")
    row(4, "Ausgabeordner:", v_out, ("Wählen …", pick_out))
    frm.columnconfigure(1, weight=1)

    logbox = scrolledtext.ScrolledText(frm, height=18, font=("Consolas", 9))
    logbox.grid(row=6, column=0, columnspan=3, sticky="nsew", pady=(10, 0))
    frm.rowconfigure(6, weight=1)

    def log(msg):
        w.after(0, lambda: (logbox.insert("end", str(msg) + "\n"), logbox.see("end")))

    def start():
        src, key, out = v_src.get().strip(), v_key.get().strip(), v_out.get().strip()
        if not src:
            messagebox.showwarning("Fehlt", "Bitte Backup-Ordner oder ZIP wählen."); return
        if not out:
            out = str(Path(src).parent / "ALEAPP_Signal_Export"); v_out.set(out)
        btn.config(state="disabled")
        logbox.delete("1.0", "end")

        def work():
            try:
                convert(src, key, out, log)
                w.after(0, lambda: messagebox.showinfo("Fertig", f"ALEAPP-Eingabe erstellt:\n{Path(out) / 'ALEAPP_Signal.zip'}"))
            except Abbruch as e:
                log(f"FEHLER: {e}")
                w.after(0, lambda: messagebox.showerror("Fehler", str(e)))
            except Exception as e:  # noqa
                import traceback
                log(traceback.format_exc())
                w.after(0, lambda: messagebox.showerror("Fehler", repr(e)))
            finally:
                w.after(0, lambda: btn.config(state="normal"))
        threading.Thread(target=work, daemon=True).start()

    btn = tk.Button(frm, text="Konvertieren für ALEAPP", command=start, bg="#2c6bed", fg="white", padx=10, pady=4)
    btn.grid(row=5, column=1, sticky="w", pady=8)
    w.mainloop()


def _hide_own_console():
    """Bei Doppelklick auf die EXE das eigene Konsolenfenster ausblenden (aus cmd gestartet: sichtbar lassen)."""
    if os.name != "nt":
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        procs = (ctypes.c_uint * 8)()
        n = k32.GetConsoleProcessList(procs, 8)
        own = 2 if getattr(sys, "frozen", False) else 1   # PyInstaller: Bootloader + Python-Prozess
        if 0 < n <= own:
            ctypes.windll.user32.ShowWindow(k32.GetConsoleWindow(), 0)
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description="Neues lokales Signal-Android-Backup in ALEAPP-Eingabe umwandeln")
    ap.add_argument("backup", nargs="?", help="Ordner SignalBackups (oder ZIP davon)")
    ap.add_argument("key_pos", nargs="?", metavar="schluessel", help="64-stelliger Wiederherstellungsschlüssel (in Anführungszeichen)")
    ap.add_argument("out_pos", nargs="?", metavar="ausgabe", help="Ausgabeordner")
    ap.add_argument("--key", help="64-stelliger Wiederherstellungsschlüssel")
    ap.add_argument("--out", help="Ausgabeordner")
    ap.add_argument("--nogui", action="store_true", help="kein Fenster, Abfrage in der Konsole")
    a = ap.parse_args()

    src = a.backup or BACKUP_ORDNER
    key = a.key or a.key_pos or SCHLUESSEL
    a.out = a.out or a.out_pos
    if not a.backup and not a.nogui:
        _hide_own_console()
    if not (src and key) and not a.nogui:
        try:
            run_gui()
            return
        except Exception as e:  # kein tkinter/Display -> Konsole
            print(f"(Fenster nicht verfügbar: {e}) – weiter in der Konsole.")
    if not src:
        src = input("Pfad zum Ordner SignalBackups (oder ZIP): ").strip().strip('"')
    if not key:
        key = getpass.getpass("64-stelliger Wiederherstellungsschlüssel (Eingabe unsichtbar): ")
    out = a.out or AUSGABE_ORDNER or str(Path(src).expanduser().parent / "ALEAPP_Signal_Export")
    try:
        convert(src, key, out)
    except Abbruch as e:
        sys.exit(f"FEHLER: {e}")
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)



DESCRIPTOR_B64 = """
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
"""

BackupInfo, Frame, LocalMetadata, FilesFrame = _load_schema()

if __name__ == "__main__":
    main()
