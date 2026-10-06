# SignalToALEAPP

[Deutsch](README.de.md) | **English**

Converts a **new local Signal Android backup** (the `SignalBackups` folder or a ZIP of it) into a pseudo extraction that [ALEAPP](https://github.com/abrignoni/ALEAPP) can read directly with its Signal parser (`scripts/artifacts/signalAndroid.py`).

This lets you review Signal chats, contacts, groups, calls, reactions and attachments from a user-created backup in the familiar ALEAPP interface, without root access or a physical extraction of the device.

> **Important:** The generated `signal.db` is a **reconstruction** from the backup, not an original file from the device. The database and attachment keys are randomly generated on every run.

> **Note:** The user interface, log messages and `report.txt` are in German.

---

## Download

The ready-to-use Windows EXE (no Python installation required) is available under **[Releases](https://github.com/AndroidIosForensik/SignalToALEAPP/releases/latest)**:

- `SignalBackup_zu_ALEAPP.exe`

Alternatively, run the Python script `signal_backup_zu_aleapp.py` directly (see below).

## Requirements

- A **local Signal backup in the new format** (Signal Android → *Settings → Chats → Chat backups*). It consists of a `SignalBackups` folder with subfolders `signal-backup-YYYY-MM-DD-…` (each containing `metadata`, `main`, `files`) and a `files` folder with the media files.
- The **64-character recovery key** (letters a–z and digits 0–9; spaces and hyphens are ignored).

Not supported:

- the **old `.backup` format** with a 30-digit numeric passphrase,
- **cloud backups** (forward-secrecy format, header `SBACKUP\x01`).

## Usage

### With the GUI (EXE or script)

1. Double-click `SignalBackup_zu_ALEAPP.exe` (or run `python signal_backup_zu_aleapp.py`).
2. Select the backup folder **or** ZIP.
3. Enter the recovery key.
4. Choose an output folder (default: `ALEAPP_Signal_Export` next to the backup).
5. Click **„Konvertieren für ALEAPP“** (Convert for ALEAPP).

### Command line

```bash
SignalBackup_zu_ALEAPP.exe "<SignalBackups folder|ZIP>" "<64 characters>" "<output folder>"
```

```bash
python signal_backup_zu_aleapp.py "<SignalBackups folder|ZIP>" --key "<64 characters>" --out "<output folder>"
```

| Option    | Meaning                                                          |
|-----------|------------------------------------------------------------------|
| `--key`   | recovery key (alternatively the 2nd positional argument)          |
| `--out`   | output folder (alternatively the 3rd positional argument)         |
| `--nogui` | don't open a window, ask for missing input in the console (key input hidden) |

If the backup folder contains several snapshots, the **newest** one is used automatically.

### Loading into ALEAPP

In ALEAPP, select `ALEAPP_Signal.zip` as input (type **zip**), or the extracted folder (type **fs**). The Signal parser finds the database, attachments and keys automatically.

## Output

```
<output folder>/
├── ALEAPP_Signal.zip
│   ├── data/data/org.thoughtcrime.securesms/databases/signal.db   (SQLCipher, as on the device)
│   ├── data/data/org.thoughtcrime.securesms/app_parts/part*.mms   (attachments, AES-CTR as on the device)
│   └── extra/Secrets/secrets.json                                 (DB key + modernKey for ALEAPP)
├── ALEAPP_Signal/   (same content, unpacked)
├── report.txt       (hashes, key derivation, statistics, notes)
└── backup.json      (complete backup content as JSON, including fields without an ALEAPP equivalent)
```

### report.txt

Among other things, the report documents:

- SHA-256 of the source files `main` and `metadata` and of the generated `ALEAPP_Signal.zip` and `signal.db`
- snapshot name, backup time, Signal app version, BackupId, determined own ACI
- number of frames, messages (including earlier versions of edited messages), reactions, calls
- attachment statistics (imported / file missing / metadata only) and media files that could not be matched

The same metadata is also stored in the `backup_conversion_info` table of the generated `signal.db`.

## How it works

1. **Decrypting** the backup: BackupKey, metadata key and BackupId are derived from the recovery key via HKDF, `main` is HMAC-verified, AES-CBC-decrypted and gunzipped.
2. **Parsing** the protobuf frames (schema from libsignal `backup.proto` / `LocalBackup.proto`, embedded in the script).
3. **Building an SQLite database** with the tables and column names of Signal Android (`recipient`, `thread`, `message`, `attachment`, `reaction`, `groups`, `group_membership`, `call`).
4. **Attachments** from `files/` are decrypted locally and re-encrypted, as Signal Android does, with AES-256-CTR and a random `modernKey`.
5. **SQLCipher encryption** of the database with Signal's parameters (4096-byte pages, PBKDF2-SHA1, HMAC-SHA1), including verification of every page.
6. Storing the keys in `extra/Secrets/secrets.json` in the format ALEAPP expects, and packing the ZIP.

## Notes for analysis

- Texts in `[square brackets]` (sticker, poll, contact, system message, call, link preview …) are generated by the converter (in German, e.g. `[Umfrage]` = poll, `[Anruf]` = call).
- System messages have no direction type, so ALEAPP shows *Direction "Unknown"*.
- Edited messages: earlier versions are separate rows with the prefix `[frühere Fassung – bearbeitet]` (earlier version – edited).
- Group IDs have the form `masterKey:<hex>`; the real Signal GroupId could only be derived via zkgroup.
- The group creation time is not included in the backup (ALEAPP: *Created Timestamp* empty).
- Calls are taken from the call system messages in the chats; the backup does not contain a separate call log.
- Content that Signal does not back up (e.g. story content, deleted messages) cannot be recovered this way either.
- All fields without an ALEAPP equivalent are fully available in `backup.json`.

## Running the Python script

Requires Python 3.9+:

```bash
pip install -r requirements.txt
```

```bash
python signal_backup_zu_aleapp.py
```

Optionally, the key, backup folder and output folder can be hard-coded at the top of the script (`SCHLUESSEL`, `BACKUP_ORDNER`, `AUSGABE_ORDNER`).

### Building the EXE yourself

```bash
pip install pyinstaller cryptography protobuf
```

```bash
pyinstaller --onefile --name SignalBackup_zu_ALEAPP signal_backup_zu_aleapp.py
```

## Disclaimer

This tool is intended for forensic analysis within legally permitted investigations. The results are a reconstruction and, like any tool output, should be verified against the source data (`backup.json`, `report.txt`). Use at your own risk.

## License

Released under the [MIT License](LICENSE).
