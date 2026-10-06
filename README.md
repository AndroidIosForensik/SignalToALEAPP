# SignalToALEAPP

Wandelt ein **neues lokales Signal-Android-Backup** (Ordner `SignalBackups` bzw. eine ZIP davon) in eine Pseudo-Extraktion um, die [ALEAPP](https://github.com/abrignoni/ALEAPP) mit seinem Signal-Parser (`scripts/artifacts/signalAndroid.py`) direkt einlesen kann.

Damit lassen sich Signal-Chats, Kontakte, Gruppen, Anrufe, Reaktionen und Anhänge aus einem vom Nutzer erstellten Backup in der gewohnten ALEAPP-Oberfläche auswerten – ohne Root-Zugriff oder physische Extraktion des Geräts.

> **Wichtig:** Die erzeugte `signal.db` ist eine **Rekonstruktion** aus dem Backup, keine Originaldatei vom Gerät. Datenbank- und Anhangschlüssel werden bei jedem Lauf zufällig neu erzeugt.

---

## Download

Die fertige Windows-EXE (keine Python-Installation nötig) gibt es unter **[Releases](https://github.com/AndroidIosForensik/SignalToALEAPP/releases/latest)**:

- `SignalBackup_zu_ALEAPP.exe`

Alternativ das Python-Skript `signal_backup_zu_aleapp.py` direkt ausführen (siehe unten).

## Voraussetzungen

- Ein **lokales Signal-Backup im neuen Format** (Signal-Android → *Einstellungen → Chats → Chat-Backups*). Es besteht aus einem Ordner `SignalBackups` mit Unterordnern `signal-backup-JJJJ-MM-TT-…` (jeweils `metadata`, `main`, `files`) sowie einem Ordner `files` mit den Mediendateien.
- Der **64-stellige Wiederherstellungsschlüssel** (Buchstaben a–z und Ziffern 0–9; Leerzeichen und Bindestriche werden ignoriert).

Nicht unterstützt:

- das **alte `.backup`-Format** mit 30-stelliger Zahlen-Passphrase,
- **Cloud-Backups** (Forward-Secrecy-Format, Header `SBACKUP\x01`).

## Benutzung

### Mit Oberfläche (EXE oder Skript)

1. `SignalBackup_zu_ALEAPP.exe` per Doppelklick starten (bzw. `python signal_backup_zu_aleapp.py`).
2. Backup-Ordner **oder** ZIP auswählen.
3. Wiederherstellungsschlüssel eingeben.
4. Ausgabeordner wählen (Standard: `ALEAPP_Signal_Export` neben dem Backup).
5. **„Konvertieren für ALEAPP“** klicken.

### Kommandozeile

```bash
SignalBackup_zu_ALEAPP.exe "<SignalBackups-Ordner|ZIP>" "<64 Zeichen>" "<Ausgabeordner>"
```

```bash
python signal_backup_zu_aleapp.py "<SignalBackups-Ordner|ZIP>" --key "<64 Zeichen>" --out "<Ausgabeordner>"
```

| Option    | Bedeutung                                                    |
|-----------|--------------------------------------------------------------|
| `--key`   | Wiederherstellungsschlüssel (alternativ 2. Positionsargument) |
| `--out`   | Ausgabeordner (alternativ 3. Positionsargument)               |
| `--nogui` | kein Fenster öffnen, fehlende Angaben in der Konsole abfragen (Schlüssel unsichtbar) |

Enthält der Backup-Ordner mehrere Snapshots, wird automatisch der **neueste** verwendet.

### In ALEAPP einlesen

In ALEAPP als Eingabe `ALEAPP_Signal.zip` wählen (Typ **zip**) – oder den entpackten Ordner (Typ **fs**). Der Signal-Parser findet Datenbank, Anhänge und Schlüssel automatisch.

## Ausgabe

```
<Ausgabeordner>/
├── ALEAPP_Signal.zip
│   ├── data/data/org.thoughtcrime.securesms/databases/signal.db   (SQLCipher, wie auf dem Gerät)
│   ├── data/data/org.thoughtcrime.securesms/app_parts/part*.mms   (Anhänge, AES-CTR wie auf dem Gerät)
│   └── extra/Secrets/secrets.json                                 (DB-Schlüssel + modernKey für ALEAPP)
├── ALEAPP_Signal/   (derselbe Inhalt entpackt)
├── report.txt       (Hashwerte, Schlüsselableitung, Statistik, Hinweise)
└── backup.json      (vollständiger Backup-Inhalt als JSON, auch Felder ohne ALEAPP-Entsprechung)
```

### report.txt

Der Bericht dokumentiert u. a.:

- SHA-256 der Quelldateien `main` und `metadata` sowie der erzeugten `ALEAPP_Signal.zip` und `signal.db`
- Snapshot-Name, Backup-Zeitpunkt, Signal-App-Version, BackupId, ermittelte eigene ACI
- Anzahl Frames, Nachrichten (inkl. älterer Fassungen bearbeiteter Nachrichten), Reaktionen, Anrufe
- Anhangstatistik (übernommen / Datei fehlt / nur Metadaten) und nicht zuordenbare Mediendateien

Die gleichen Metadaten stehen zusätzlich in der Tabelle `backup_conversion_info` der erzeugten `signal.db`.

## Funktionsweise

1. **Entschlüsseln** des Backups: Ableitung von BackupKey, Metadaten-Schlüssel und BackupId per HKDF aus dem Wiederherstellungsschlüssel, HMAC-Prüfung von `main`, AES-CBC-Entschlüsselung und gzip-Entpacken.
2. **Parsen** der Protobuf-Frames (Schema aus libsignal `backup.proto` / `LocalBackup.proto`, im Skript eingebettet).
3. **Aufbau einer SQLite-Datenbank** mit den Tabellen und Spaltennamen von Signal-Android (`recipient`, `thread`, `message`, `attachment`, `reaction`, `groups`, `group_membership`, `call`).
4. **Anhänge** werden aus `files/` lokal entschlüsselt und – wie Signal-Android es tut – mit AES-256-CTR und einem zufälligen `modernKey` neu verschlüsselt.
5. **SQLCipher-Verschlüsselung** der Datenbank mit Signals Parametern (4096-Byte-Seiten, PBKDF2-SHA1, HMAC-SHA1) inklusive Gegenprüfung jeder Seite.
6. Ablage der Schlüssel in `extra/Secrets/secrets.json` im von ALEAPP erwarteten Format und Packen der ZIP.

## Hinweise zur Auswertung

- Texte in `[eckigen Klammern]` (Sticker, Umfrage, Kontakt, Systemmeldung, Anruf, Link-Vorschau …) werden vom Konverter erzeugt.
- Systemmeldungen haben keinen Richtungstyp – ALEAPP zeigt *Direction „Unknown“*.
- Bearbeitete Nachrichten: ältere Fassungen sind eigene Zeilen mit dem Präfix `[frühere Fassung – bearbeitet]`.
- Gruppen-IDs haben die Form `masterKey:<hex>`; die echte Signal-GroupId wäre nur per zkgroup ableitbar.
- Die Gruppenerstellungszeit ist im Backup nicht enthalten (ALEAPP: *Created Timestamp* leer).
- Anrufe stammen aus den Anruf-Systemmeldungen der Chats; eine separate Anrufliste enthält das Backup nicht.
- Inhalte, die Signal nicht sichert (z. B. Story-Inhalte, gelöschte Nachrichten), kann auch dieser Weg nicht liefern.
- Alle Felder ohne ALEAPP-Entsprechung stehen vollständig in `backup.json`.

## Python-Skript ausführen

Benötigt Python 3.9+:

```bash
pip install -r requirements.txt
```

```bash
python signal_backup_zu_aleapp.py
```

Optional können Schlüssel, Backup- und Ausgabeordner oben im Skript (`SCHLUESSEL`, `BACKUP_ORDNER`, `AUSGABE_ORDNER`) fest eingetragen werden.

### EXE selbst bauen

```bash
pip install pyinstaller cryptography protobuf
```

```bash
pyinstaller --onefile --name SignalBackup_zu_ALEAPP signal_backup_zu_aleapp.py
```

## Haftungsausschluss

Das Tool ist für forensische Auswertungen im Rahmen rechtlich zulässiger Untersuchungen gedacht. Die Ergebnisse sind eine Rekonstruktion und sollten – wie jede Toolausgabe – gegen die Quelldaten (`backup.json`, `report.txt`) verifiziert werden. Nutzung auf eigene Verantwortung.

## Lizenz

Veröffentlicht unter der [MIT-Lizenz](LICENSE).
