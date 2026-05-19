# RDOC-CamHub Security Findings

Datum: 2026-05-19  
Scope: aktueller Skeleton-Stand von RDOC-CamHub im Verzeichnis `/Users/te/Projekte/private/RDOC-CamHub`.

Letzter Recheck: 2026-05-19 nach M0.5-Sicherheitsarbeiten. `go test ./...` laeuft erfolgreich; `internal/httpapi` hat inzwischen Security-nahe Tests fuer Cookie-Konfiguration, Trusted Proxy IP und Login-Rate-Limiting.

## Kurzfazit

RDOC-CamHub ist derzeit ein frueher Skeleton mit `/healthz`, Login, Logout, `/me`, Postgres-Migrationen und Admin-Bootstrap. Die kritischsten Risiken liegen nicht in SQL-Injection oder Passwort-Hashing, sondern in fehlenden architektonischen Sicherheitsgrenzen: Cookie-Sicherheit hinter Reverse Proxy, fehlendes Rate Limiting, fehlende zentrale AuthZ-Middleware und noch nicht systemisch vorhandener CSRF-Schutz.

Beim ersten Review wurde `go test ./...` erfolgreich ausgefuehrt, damals noch ohne Testdateien. Beim Recheck am 2026-05-19 existieren inzwischen Tests in `internal/httpapi`; `go test ./...` laeuft weiterhin erfolgreich.

## Recheck 2026-05-19

Dieser Abschnitt bewertet den aktuellen Stand nach den inzwischen vorhandenen Aenderungen:

- `internal/config/config.go` enthaelt jetzt `CookieSecure`, `CookieDomain` und `TrustedProxies`.
- `internal/httpapi/cookie.go` kapselt Cookie-Attribute.
- `internal/httpapi/trusted_ip.go` ersetzt die vorherige direkte Nutzung von `middleware.RealIP`.
- `internal/httpapi/rate_limit.go` fuehrt ein In-Process-Rate-Limit fuer Login ein.
- `deploy/Caddyfile.prod` wurde als produktive Caddy-Konfiguration hinzugefuegt.
- `go test ./...` laeuft erfolgreich.

### Statusmatrix

| Finding | Status nach Recheck | Bemerkung |
|---|---|---|
| SEC-001 | Teilweise behoben | Cookie-Secure ist nun konfigurierbar und produktiv default `true`; Compose setzt fuer lokale Entwicklung bewusst `CAMHUB_DEV_INSECURE_COOKIE=1`. |
| SEC-002 | Teilweise behoben | Body-Limit, Laengenlimits und Login-Rate-Limit existieren. Siehe neues Finding SEC-011 zur Fail-Open-Logik bei ungueltiger Client-IP. |
| SEC-003 | Offen | Zentrale `RequireSession`-/`RequireRole`-Middleware fehlt weiterhin; `/me` prueft Session noch selbst. |
| SEC-004 | Offen | CSRF-Schutz fehlt weiterhin fuer cookie-authentisierte mutierende Requests. |
| SEC-005 | Offen, aber dokumentiert | `CAMHUB_SESSION_KEY` wird weiterhin geladen, aber nicht verwendet; README markiert das inzwischen als bekanntes Thema. |
| SEC-006 | Teilweise behoben | Trusted-Proxy-Middleware existiert und wird getestet. Siehe SEC-012 zur produktiven Caddy-Header-Weitergabe. |
| SEC-007 | Offen | Bootstrap nutzt weiterhin `--password`; README zeigt weiterhin ein Inline-Passwort. |
| SEC-008 | Teilweise behoben | `deploy/Caddyfile.prod` existiert mit HTTPS-Hosts und Security-Headern. |
| SEC-009 | Offen | Session-TTL bleibt 7 Tage; kein Purge-Loop/Refresh-Modell implementiert. |
| SEC-010 | Teilweise behoben | `internal/httpapi` hat Tests; Auth-/Password-/Config-Tests fehlen weiterhin. |

### Neue Findings aus dem Recheck

## Finding SEC-011: Login-Rate-Limiter laesst Requests ohne gueltige Client-IP durch

Severity: Medium  
Status: Open  
Kategorie: Authentication / DoS Resistance  
Betroffene Dateien:

- `internal/httpapi/rate_limit.go`
- `internal/httpapi/trusted_ip.go`

### Evidenz

Der Rate-Limiter liest die IP aus dem Request-Kontext:

- `internal/httpapi/rate_limit.go:27`

Wenn keine gueltige IP vorhanden ist, wird der Request durchgelassen:

- `internal/httpapi/rate_limit.go:31-33`

Der Kommentar sagt "fail closed", die Implementierung ist aber fail-open. `ClientIP` kann einen Zero-Addr liefern, wenn `RemoteAddr` leer oder unparsbar ist:

- `internal/httpapi/trusted_ip.go:12-17`
- `internal/httpapi/trusted_ip.go:89-100`

### Risiko

In normalen `net/http`-Serverpfaden ist `RemoteAddr` meist gesetzt. Trotzdem ist die Sicherheitsinvariante schwach: Sobald ein Test, Proxy, Spezial-Transport oder zukuenftiger Handler-Pfad ohne parsbare IP durchgeht, wird ausgerechnet der Login-Rate-Limiter deaktiviert. Das widerspricht dem Kommentar und erschwert belastbare DoS-Abwehr.

### Empfohlener Fix

Claude-Code-Aufgabe:

1. Aendere `internal/httpapi/rate_limit.go`, sodass ungueltige Client-IP nicht den Rate-Limiter umgeht.
2. Entweder: Request mit `500`/`400` ablehnen, wenn Client-IP fehlt, oder alle unbekannten Clients in einen gemeinsamen `"unknown"`-Bucket legen.
3. Passe den Kommentar an die tatsaechliche Strategie an.
4. Ergaenze einen Test, der einen Request ohne Client-IP nicht frei passieren laesst.

Akzeptanzkriterien:

- Rate-Limiting kann nicht durch fehlende/unparsbare Client-IP deaktiviert werden.
- Kommentar und Verhalten stimmen ueberein.

## Finding SEC-012: Produktions-Caddyfile ueberschreibt statt erweitert `X-Forwarded-For`

Severity: Medium  
Status: Open  
Kategorie: Proxy Trust / Audit / Rate Limiting  
Betroffene Dateien:

- `deploy/Caddyfile.prod`
- `internal/httpapi/trusted_ip.go`

### Evidenz

Die produktive Caddyfile setzt `X-Forwarded-For` explizit auf `{remote_host}`:

- `deploy/Caddyfile.prod:37-39`
- `deploy/Caddyfile.prod:47-49`

Die Trusted-Proxy-Logik im Go-Code kann eine XFF-Kette von rechts nach links auswerten:

- `internal/httpapi/trusted_ip.go:54-74`

Wenn Caddy aber die Header-Kette ueberschreibt, gehen vorgelagerte Proxy-Hops verloren. Das ist in Setups ohne vorgelagerten Proxy okay. Hinter Cloudflare, Load Balancern oder weiteren Reverse Proxies kann es aber dazu fuehren, dass CamHub nicht den echten Client, sondern nur den letzten Proxy sieht.

### Risiko

Audit-Logs, Session-IP und Login-Rate-Limiting koennen auf den letzten Proxy statt auf den echten Client aggregieren. Das kann viele Nutzer in einen gemeinsamen Rate-Limit-Bucket werfen oder Angreifer hinter grossen Proxy-Netzen schwerer unterscheidbar machen.

### Empfohlener Fix

Claude-Code-Aufgabe:

1. Entscheide, ob Produktion direkt am Internet haengt oder hinter Cloudflare/weiteren Proxies.
2. Wenn direkte Internetkante: Dokumentiere explizit, dass `header_up X-Forwarded-For {remote_host}` absichtlich eingehende XFF-Header scrubbt.
3. Wenn vorgelagerte Proxies erlaubt sind: Nutze eine Caddy-Konfiguration, die die echte Client-IP sicher aus dem vertrauenswuerdigen Edge-Header bezieht, z. B. Cloudflare-spezifisch `CF-Connecting-IP`, und setze `CAMHUB_TRUSTED_PROXIES` entsprechend eng.
4. Fuege Deployment-Dokumentation hinzu, welche CIDRs in `CAMHUB_TRUSTED_PROXIES` fuer Prod erlaubt sind.

Akzeptanzkriterien:

- Prod-Doku macht klar, welche Proxy-Kette unterstuetzt wird.
- Login-Rate-Limit nutzt in dieser Proxy-Kette die beabsichtigte Client-IP.

## Finding SEC-013: Lokales `cookies.txt` enthaelt ein Session-Token und ist nicht ignoriert

Severity: Low-Medium  
Status: Open  
Kategorie: Secret Hygiene  
Betroffene Dateien:

- `cookies.txt`
- `.gitignore`

### Evidenz

Im Repo liegt `cookies.txt`; es enthaelt ein `camhub_session` Cookie. Die Datei ist aktuell untracked, aber `.gitignore` ignoriert sie nicht:

- `cookies.txt`
- `.gitignore`

### Risiko

Session-Cookies sind Secrets. Auch wenn dieses Cookie lokal/dev ist, kann so eine Datei versehentlich committed, geteilt oder in Logs kopiert werden.

### Empfohlener Fix

Claude-Code-Aufgabe:

1. Loesche die lokale `cookies.txt`, wenn sie nicht mehr gebraucht wird.
2. Fuege `cookies.txt` oder allgemeiner `*.cookies.txt` zu `.gitignore` hinzu.
3. Passe README-Smoke-Tests optional so an, dass Cookie-Jars in `/tmp` geschrieben werden.

Akzeptanzkriterien:

- `git status --short` zeigt keine lokale Cookie-Jar-Datei mehr.
- Zukuenftige Smoke-Test-Cookies werden nicht versehentlich versioniert.

## Finding SEC-001: Session-Cookie wird hinter TLS-Reverse-Proxy nicht sicher gesetzt

Severity: High  
Status: Open  
Kategorie: Session Management / Deployment Architecture  
Betroffene Dateien:

- `internal/httpapi/auth.go`
- `deploy/Caddyfile`
- `docker-compose.yml`

### Evidenz

In `internal/httpapi/auth.go` wird das Session-Cookie beim Login mit `Secure: r.TLS != nil` gesetzt:

- `internal/httpapi/auth.go:63-70`

Beim Logout wird dieselbe Bedingung verwendet:

- `internal/httpapi/auth.go:86-93`

Die geplante und vorhandene Deployment-Architektur terminiert TLS aber in Caddy und proxyt danach intern per HTTP weiter:

- `deploy/Caddyfile:13-15`
- `docker-compose.yml:38-49`

Dadurch ist `r.TLS` im Go-Server in Produktion typischerweise `nil`, obwohl der Browser HTTPS spricht. Das Cookie wird dann ohne `Secure`-Attribut ausgeliefert.

### Risiko

Ein nicht-`Secure` Session-Cookie kann bei HTTP-Requests an dieselbe Domain mitgesendet werden. In Kombination mit fehlender produktiver HSTS-Konfiguration kann das Session-Token leichter abgegriffen oder in Downgrade-/Mixed-Deployment-Situationen exponiert werden.

### Empfohlener Fix

Fuehre eine explizite Cookie-Sicherheitskonfiguration ein und kopple sie nicht an `r.TLS` im Backend.

Claude-Code-Aufgabe:

1. Erweitere `internal/config/config.go` um z. B. `CookieSecure bool` und optional `CookieDomain string`.
2. Setze `CookieSecure` default-maessig fuer Produktion auf `true`; fuer lokale Entwicklung kann ein expliziter Dev-Schalter erlaubt sein.
3. Uebergib die Config oder einen kleinen `SessionCookieConfig` an `httpapi.Server`.
4. Ersetze in `internal/httpapi/auth.go` beide Vorkommen von `Secure: r.TLS != nil` durch die zentrale Einstellung.
5. Ergaenze Tests fuer Login-Cookie und Logout-Cookie.
6. Ergaenze produktive Caddy-Header, mindestens HSTS fuer echte HTTPS-Hosts.

Akzeptanzkriterien:

- Produktiv gesetzte Session-Cookies haben immer `HttpOnly`, `Secure`, `SameSite=Lax` oder strenger.
- Das Verhalten ist testbar, ohne echte TLS-Verbindung im Go-Test aufzubauen.
- Lokale HTTP-Entwicklung ist nur ueber explizite Dev-Konfiguration moeglich.

## Finding SEC-002: Login hat kein Rate Limiting und keine Request-Groessenlimits

Severity: High  
Status: Open  
Kategorie: Authentication / DoS Resistance  
Betroffene Dateien:

- `internal/httpapi/router.go`
- `internal/httpapi/auth.go`
- `internal/auth/password.go`

### Evidenz

`POST /v1/auth/login` ist oeffentlich registriert:

- `internal/httpapi/router.go:42-46`

Jeder Loginversuch fuehrt Argon2id aus:

- `internal/httpapi/auth.go:32-48`
- `internal/auth/password.go:43-71`

Es gibt aktuell kein Rate Limiting, keine maximale JSON-Body-Groesse und keine harten Laengenlimits fuer Email oder Passwort.

### Risiko

Ein Angreifer kann mit vielen Loginversuchen CPU und Speicher binden, weil Argon2id bewusst teuer ist. Gleichzeitig bleibt Passwort-Raten gegen bekannte Accounts ungebremst.

### Empfohlener Fix

Fuehre mehrstufige Login-Schutzmechanismen ein.

Claude-Code-Aufgabe:

1. Begrenze den Login-Request-Body in `login` mit `http.MaxBytesReader`, z. B. 4 KiB.
2. Validere Email- und Passwortlaengen vor Argon2id, z. B. Email <= 320 Zeichen, Passwort <= 1024 Zeichen.
3. Fuehre Rate Limiting fuer `/v1/auth/login` ein, mindestens pro Client-IP und optional pro normalisierter Email.
4. Nutze fuer IP-Ermittlung eine vertrauenswuerdige Proxy-Strategie; siehe SEC-006.
5. Fuege Tests fuer Body-Limit, Passwortlaenge und Rate-Limit-Verhalten hinzu.

Akzeptanzkriterien:

- Viele Loginversuche von derselben IP werden mit `429 Too Many Requests` beantwortet.
- Uebergrosse Bodies werden vor JSON-Decoding abgelehnt.
- Sehr lange Passwoerter werden vor Argon2id abgelehnt.
- Fehlermeldungen unterscheiden weiterhin nicht zwischen "User existiert nicht" und "Passwort falsch".

## Finding SEC-003: Zentrale AuthN/AuthZ-Schicht fehlt

Severity: Medium  
Status: Open  
Kategorie: Authorization Architecture  
Betroffene Dateien:

- `internal/httpapi/router.go`
- `internal/httpapi/auth.go`
- `internal/db/users.go`

### Evidenz

`/v1/auth/me` liest das Session-Cookie direkt im Handler und laedt die Session selbst:

- `internal/httpapi/auth.go:98-129`

Routen werden direkt auf Handler gebunden:

- `internal/httpapi/router.go:42-47`

Es existiert keine zentrale Middleware fuer:

- Session-Validierung
- Principal im Request-Kontext
- Rollenpruefung (`admin`, `operator`, `viewer`)
- spaetere API-Token-/Scope-Pruefung

### Risiko

Wenn die geplanten Device-, Enrollment-, OBS- und Admin-Endpunkte dazukommen, muss jeder Handler seine eigene Authentisierung und Autorisierung korrekt implementieren. Das erhoeht das Risiko von versehentlich oeffentlichen Admin- oder Operator-Endpunkten.

### Empfohlener Fix

Baue Authentisierung und Autorisierung als explizite Router-Grenze.

Claude-Code-Aufgabe:

1. Erstelle in `internal/httpapi` eine zentrale Middleware, z. B. `RequireSession`.
2. Lege einen `Principal`-Typ an, z. B. `UserID`, `Email`, `Role`, `SessionID`.
3. Speichere den Principal im Request-Kontext.
4. Erstelle Rollen-Middleware, z. B. `RequireRole(db.RoleViewer)`, `RequireRole(db.RoleOperator)`, `RequireRole(db.RoleAdmin)`.
5. Passe `/v1/auth/me` so an, dass es den Principal aus dem Kontext liest.
6. Definiere im Router explizit Public-, Authenticated- und Admin-Gruppen.

Akzeptanzkriterien:

- Neue geschuetzte Routen koennen nicht ohne sichtbare Middleware-Gruppe registriert werden.
- Rollenpruefung ist zentral testbar.
- `/v1/auth/me` funktioniert weiter und nutzt dieselbe Session-Validierung wie zukuenftige geschuetzte Endpunkte.

## Finding SEC-004: CSRF-Schutz ist nicht systemisch implementiert

Severity: Medium  
Status: Open  
Kategorie: Browser Security / CSRF  
Betroffene Dateien:

- `internal/httpapi/router.go`
- `internal/httpapi/auth.go`

### Evidenz

Session-Cookies werden mit `SameSite=Lax` gesetzt:

- `internal/httpapi/auth.go:63-70`

Es gibt aber keine CSRF-Middleware, keinen Double-Submit-Token und keine Origin-/Referer-Pruefung fuer mutierende cookie-authentisierte Requests. Aktuell betrifft das vor allem Logout:

- `internal/httpapi/auth.go:79-95`

Die geplanten Admin- und Device-Management-Endpunkte werden mutierende Browser-Requests haben.

### Risiko

`SameSite=Lax` reduziert CSRF-Risiko, ersetzt aber keinen konsistenten Schutz fuer alle state-changing Browser-Requests. Sobald Admin-/Operator-Aktionen per Cookie-Session hinzukommen, koennen Cross-Site-Requests gefaehrlich werden.

### Empfohlener Fix

Fuehre eine CSRF-Strategie ein, bevor Admin- und Device-Mutationsrouten wachsen.

Claude-Code-Aufgabe:

1. Entscheide eine CSRF-Strategie: Double-Submit-Cookie plus Header oder serverseitiger Token pro Session.
2. Schuetze alle `POST`, `PUT`, `PATCH`, `DELETE` Requests, die Cookie-Sessions nutzen.
3. Lasse reine Bearer-Token/API-Token-Flows ohne Cookie separat behandeln.
4. Pruefe zusaetzlich `Origin`/`Referer` fuer Browser-Requests, wenn moeglich.
5. Fuege Tests fuer fehlenden, falschen und korrekten CSRF-Token hinzu.

Akzeptanzkriterien:

- Mutierende Cookie-Requests ohne CSRF-Token werden abgelehnt.
- Login bleibt nutzbar; fuer Login kann Rate Limiting wichtiger sein als CSRF.
- API-Token-Flows werden nicht versehentlich durch Browser-CSRF-Mechanik gebrochen.

## Finding SEC-005: `CAMHUB_SESSION_KEY` wird verlangt, aber nicht fuer Session-Schutz verwendet

Severity: Medium  
Status: Open  
Kategorie: Configuration / Session Design  
Betroffene Dateien:

- `internal/config/config.go`
- `internal/auth/session.go`
- `internal/httpapi/auth.go`
- `README.md`

### Evidenz

Die Konfiguration verlangt einen Session-Key:

- `internal/config/config.go:30-37`

README beschreibt ihn als Key fuer signierte Session-Cookies:

- `README.md:53-60`

Die eigentliche Session-Cookie enthaelt aber nur eine rohe zufaellige Session-ID:

- `internal/auth/session.go:9-16`
- `internal/httpapi/auth.go:63-70`

Der geladene `SessionKey` wird im HTTP-Server nicht verwendet.

### Risiko

Das ist nicht automatisch ein unmittelbarer Exploit, weil serverseitige zufaellige Session-IDs ein valides Design sein koennen. Es erzeugt aber eine falsche Sicherheitsannahme: Rotation, Signatur und Key-Management wirken implementiert, sind es aber nicht. Spaetere Aenderungen koennen dadurch auf einer falschen Architekturannahme aufbauen.

### Empfohlener Fix

Entscheide und dokumentiere ein klares Session-Modell.

Claude-Code-Aufgabe:

Option A: Serverseitige Session-ID beibehalten.

1. Entferne `SessionKey` aus der zwingenden Runtime-Konfiguration.
2. Passe README und Compose-Secrets an.
3. Dokumentiere, dass Session-Sicherheit auf zufaelliger ID plus DB-Store beruht.

Option B: Signierte Cookie-Werte einfuehren.

1. Verwende `SessionKey` tatsaechlich, z. B. fuer HMAC-signierte Session-ID.
2. Implementiere Key-Rotation oder zumindest klare Rotation-Dokumentation.
3. Teste manipulierte Cookie-Werte.

Akzeptanzkriterien:

- Code, README und Compose beschreiben dasselbe Sicherheitsmodell.
- Kein Secret wird geladen, ohne eine Sicherheitsfunktion zu erfuellen.

## Finding SEC-006: `middleware.RealIP` wird ohne Trust-Boundary-Konfiguration genutzt

Severity: Medium  
Status: Open  
Kategorie: Proxy Trust / Audit / Rate Limiting  
Betroffene Dateien:

- `internal/httpapi/router.go`
- `internal/httpapi/auth.go`

### Evidenz

Der Router nutzt `middleware.RealIP` global:

- `internal/httpapi/router.go:35-38`

Login speichert danach `r.RemoteAddr` als Session-IP:

- `internal/httpapi/auth.go:56-57`

Chi `RealIP` wertet Forwarding-Header aus. Ohne klare Trust Boundary duerfen diese Header nur von einem vertrauenswuerdigen Reverse Proxy kommen.

### Risiko

Wenn CamHub direkt erreichbar ist oder ein Proxy Forwarding-Header nicht bereinigt, koennen Clients ihre IP fuer Logs, Sessions und zukuenftiges Rate Limiting faelschen. Das untergraebt SEC-002, Auditierbarkeit und Anomalieerkennung.

### Empfohlener Fix

Mache Proxy-Vertrauen explizit.

Claude-Code-Aufgabe:

1. Stelle sicher, dass `camhub` produktiv nur intern erreichbar ist; Compose bindet aktuell `127.0.0.1:8080`, das ist fuer lokalen Betrieb gut.
2. Ersetze oder kapsle `middleware.RealIP` so, dass Forwarded Headers nur von konfigurierten Trusted Proxies akzeptiert werden.
3. Dokumentiere die erwartete Proxy-Kette.
4. Nutze dieselbe IP-Ermittlung fuer Logging, Rate Limiting und Session-Audit.

Akzeptanzkriterien:

- Direktzugriffe koennen `X-Forwarded-For` nicht zum IP-Spoofing nutzen.
- Tests decken vertrauenswuerdige und nicht vertrauenswuerdige Proxy-Quellen ab.

## Finding SEC-007: Admin-Bootstrap-Passwort wird per CLI-Argument uebergeben

Severity: Low-Medium  
Status: Open  
Kategorie: Secret Handling / Operational Security  
Betroffene Dateien:

- `cmd/camhub/bootstrap.go`
- `cmd/camhub/main.go`
- `README.md`

### Evidenz

Der Bootstrap-Befehl nimmt das Passwort als Flag:

- `cmd/camhub/bootstrap.go:16-27`
- `cmd/camhub/main.go:51-53`

README empfiehlt ebenfalls `--password 'change-me'`:

- `README.md:26-29`

### Risiko

Passwoerter in CLI-Argumenten koennen in Shell-History, Prozesslisten, Terminal-Logs oder Container-Exec-Auditdaten auftauchen.

### Empfohlener Fix

Erlaube sichere Eingabequellen fuer Bootstrap-Secrets.

Claude-Code-Aufgabe:

1. Implementiere `--password-file`.
2. Optional: Wenn `--password` fehlt, Passwort interaktiv ueber TTY lesen.
3. Entferne oder de-priorisiere `--password` in README-Beispielen.
4. Gib bei Nutzung von `--password` eine Warnung aus oder markiere es als Dev-only.

Akzeptanzkriterien:

- README zeigt kein Passwort mehr als CLI-Argument.
- Bootstrap funktioniert mit Secret-Datei.
- Mindestlaenge bleibt erhalten.

## Finding SEC-008: Produktions-Caddy-Konfiguration ist nur ein Placeholder

Severity: Low-Medium  
Status: Open  
Kategorie: Deployment Hardening  
Betroffene Dateien:

- `deploy/Caddyfile`
- `docker-compose.yml`

### Evidenz

Aktiv ist nur ein Plain-HTTP-VHost:

- `deploy/Caddyfile:12-16`

Produktionshosts sind auskommentiert:

- `deploy/Caddyfile:18-28`

### Risiko

Fuer ein Control-Plane-Projekt ist eine sichere Produktionskonfiguration Teil der Architektur. Placeholder-Konfigurationen fuehren leicht dazu, dass HTTP, fehlendes HSTS oder unklare Host-Trennung laenger bestehen bleiben als geplant.

### Empfohlener Fix

Trenne Dev- und Prod-Konfiguration klar.

Claude-Code-Aufgabe:

1. Lege eine produktive Caddyfile oder dokumentierte Compose-Override-Datei an.
2. Aktiviere HTTPS fuer `api.raumdock.org` und `app.raumdock.org`.
3. Setze HSTS nur fuer echte HTTPS-Hosts.
4. Pruefe Security Header wie `X-Content-Type-Options`, `Referrer-Policy` und eine spaetere CSP fuer das UI.
5. Stelle sicher, dass der direkte CamHub-Port produktiv nicht oeffentlich exponiert ist.

Akzeptanzkriterien:

- Dev und Prod sind klar getrennt.
- Produktive Konfiguration erzwingt HTTPS.
- Security-Header sind an einer zentralen Stelle sichtbar.

## Finding SEC-009: Session-Lebensdauer weicht vom Sicherheitsplan ab

Severity: Low-Medium  
Status: Open  
Kategorie: Session Lifecycle  
Betroffene Dateien:

- `internal/auth/session.go`
- `Plan.md`
- `internal/db/sessions.go`

### Evidenz

Aktuell ist die Session-TTL konstant 7 Tage:

- `internal/auth/session.go:9`

Der Plan beschreibt kurzlebige Session-Cookies mit 15 Minuten plus rotierendem Refresh Token:

- `Plan.md:91-93`

Die Tabelle hat `refreshed_at`, aber es gibt keine Refresh-/Rotation-Logik:

- `internal/migrations/00001_init.sql:13-21`
- `internal/db/sessions.go:28-36`

### Risiko

Ein gestohlenes Session-Cookie bleibt deutlich laenger nutzbar als geplant. Ohne Rotation, Device-Binding oder Reauth fuer Admin-Aktionen steigt der Schaden bei Cookie-Diebstahl.

### Empfohlener Fix

Entscheide den Zielzustand fuer v1 und implementiere ihn konsistent.

Claude-Code-Aufgabe:

1. Entweder Plan anpassen: 7-Tage-Session bewusst akzeptieren und Risiko dokumentieren.
2. Oder Plan umsetzen: kurze Access-Session plus Refresh-Token mit Rotation.
3. Fuege Session-Purge oder regelmaessigen Cleanup-Aufruf hinzu; `PurgeExpired` existiert, wird aber aktuell nicht aufgerufen.
4. Optional: Admin-Aktionen mit Reauth-Zeitfenster absichern.

Akzeptanzkriterien:

- Session-TTL im Code entspricht der Dokumentation.
- Abgelaufene Sessions werden geloescht oder zumindest nicht unbegrenzt gesammelt.
- Kritische Admin-Aktionen koennen spaeter eine frische Authentisierung verlangen.

## Finding SEC-010: Keine Security-Tests fuer Auth-Flows

Severity: Low-Medium  
Status: Open  
Kategorie: Test Coverage  
Betroffene Dateien:

- `internal/httpapi/auth.go`
- `internal/httpapi/router.go`
- `internal/auth/password.go`

### Evidenz

`go test ./...` laeuft, aber alle Pakete melden `[no test files]`.

### Risiko

Auth-, Cookie- und Security-Header-Verhalten kann unbemerkt regressieren. Gerade die Reverse-Proxy-Cookie-Sicherheit aus SEC-001 ist ohne Test leicht wieder falsch zu implementieren.

### Empfohlener Fix

Fuege fokussierte Security-Tests fuer Auth- und Middleware-Verhalten hinzu.

Claude-Code-Aufgabe:

1. Tests fuer Passwort-Hash/Verify inklusive falschem Passwort und ungueltigem Hash.
2. Handler-Tests fuer Login-Cookie-Flags.
3. Handler-Tests fuer `/v1/auth/me` ohne Cookie, mit ungueltiger Session und mit gueltiger Session.
4. Nach Fixes: Tests fuer Rate Limit, CSRF und Rollen-Middleware.

Akzeptanzkriterien:

- `go test ./...` prueft mindestens die Kern-Sicherheitsinvarianten von Login und Session.
- Cookie-Flags koennen nicht ohne Testbruch entfernt werden.

## Priorisierte Fix-Reihenfolge

1. SEC-001: Cookie-Secure hinter Reverse Proxy fixen.
2. SEC-002: Login-Rate-Limiting und Request-Limits einfuehren.
3. SEC-003: Zentrale AuthN/AuthZ-Middleware bauen, bevor neue Endpunkte entstehen.
4. SEC-004: CSRF-Schutz vor Admin-/Device-Mutationsrouten implementieren.
5. SEC-006: Trusted-Proxy/IP-Modell klaeren, damit Rate Limiting und Audit belastbar sind.
6. SEC-005, SEC-007, SEC-008, SEC-009, SEC-010 danach in kurzen PRs abarbeiten.

## Hinweise fuer Claude Code

- Keine grossen Refactors ausserhalb von `internal/httpapi`, `internal/config`, `internal/auth`, `cmd/camhub` und Deploy-Dateien starten, solange sie nicht direkt zur jeweiligen SEC-Aufgabe gehoeren.
- Die geplanten Device-/OBS-/Admin-Endpunkte aus `Plan.md` noch nicht nebenbei implementieren. Erst die Sicherheitsbasis stabilisieren.
- Bestehende Docker-Secrets beibehalten; keine Secrets in Inline-Env oder README-Beispiele einfuehren.
- Nach jeder Fix-Gruppe `go test ./...` ausfuehren.
