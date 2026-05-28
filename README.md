# VulnerApp Whitehat

## Erfuellte Kernanforderungen (8 Punkte)

1. Korrekte REST-Verben
   - Admin-Endpunkte sind jetzt korrekt als `POST /api/admin/users`, `GET /api/admin/users`, `DELETE /api/admin/users/{username}` umgesetzt.

2. Session-basierte Authentifizierung
   - Login via Spring Security Form-Login, mit Session-Cookie (`JSESSIONID`).

3. RBAC (Role-Based Access Control)
   - `ADMIN`: Zugriff auf `/api/admin/**` und nicht-Health-Actuator-Endpunkte.
   - `USER` + `ADMIN`: Zugriff auf `/api/user/**` und `POST /api/blog`.
   - Anonymous: nur erlaubte Public-Endpunkte.

4. CSRF-Protection aktiv + warum sie funktioniert
   - Aktiv via `CookieCsrfTokenRepository`.
   - Der Server setzt ein `XSRF-TOKEN` Cookie.
   - Bei state-changing Requests (z. B. `POST`, `DELETE`) muss derselbe Token im Header `X-XSRF-TOKEN` mitgesendet werden.
   - Ein fremdes Formular/Script kann diesen Abgleich nicht korrekt liefern, deshalb werden CSRF-Angriffe geblockt.

5. Sichere Passwort-Speicherung + Passwortregeln
   - Passwort-Hashing mit `BCryptPasswordEncoder`.
   - Passwortregeln in `UserCreateDto` (min. Laenge, Gross-/Kleinbuchstaben, Zahl).

6. Strikte Inputvalidierung (REST + Datenmodell)
   - Bean Validation mit `jakarta.validation` in DTOs/Entities (`@NotBlank`, `@Size`, `@Pattern`).
   - Validierung aktiv in Controllern mit `@Valid`.

7. Initiale Sicherheitsluecken behoben
   - SQLi: unsichere native String-Query entfernt, stattdessen Repository-Zugriff.
   - XSS: Blog-Ausgabe im Frontend mit `textContent` statt `innerHTML`.
   - CSRF: serverseitig aktiviert und clientseitig korrekt genutzt.

8. Security-Tests mit WebTestClient gemaess Tabelle
   - `VulnerApplicationTests` deckt die Matrix fuer:
     - `GET /`
     - `GET /api/blog`
     - `POST /api/blog`
     - `GET /api/user/whoami`
     - `/api/admin/*`
     - `GET /actuator/health`
   - Szenarien: anonymous, User ohne CSRF, User mit CSRF, Admin mit CSRF.

## Starten

```console
./gradlew bootRun
```

## Reflexion

### Welche Sicherheitsmechanismen wurden wo umgesetzt und warum?

- Authentifizierung und Autorisierung wurden zentral in `SecurityConfiguration` umgesetzt. Das reduziert Inkonsistenzen, weil Zugriffsregeln nicht verteilt in vielen Klassen gepflegt werden muessen.
- Session-basierte Anmeldung ist fuer dieses Projekt passend, weil das Frontend ein klassisches Browser-Frontend ist und Cookies automatisch mitgesendet werden.
- RBAC trennt User- und Admin-Funktionen klar. Dadurch wird verhindert, dass normale User administrative Funktionen aufrufen koennen.
- CSRF-Schutz funktioniert hier, weil fuer schreibende Requests ein gueltiger Token als Cookie und Header vorliegen muss.
- Passwort-Hashing mit BCrypt reduziert das Risiko bei Datenabfluss, da keine Klartext-Passwoerter gespeichert sind.
- Inputvalidierung auf DTO- und Entity-Ebene verhindert ungueltige oder manipulative Eingaben frueh im Request-Lebenszyklus.

### Weitere sinnvolle Sicherheitsmassnahmen

- Rate Limiting fuer Login-Endpunkte, um Brute-Force-Angriffe zu erschweren.
- Account-Lockout oder progressive Delays nach mehreren Fehlversuchen.
- Strukturierte Security-Logs mit Alarmierung bei auffaelligen Zugriffsmustern.
- Striktere Security-Header (z. B. HSTS in Produktion) und CSP weiter haerten.
- Optional: OIDC/OAuth2-Login, falls zentrale Identitaetsverwaltung benoetigt wird.

### Schwierigkeiten und was ich anders machen wuerde

- Die groesste Schwierigkeit war, alle Abhaengigkeiten zwischen CSRF, Session, Frontend und Tests konsistent zu halten.
- Beim Umstellen von unsicheren Endpunkten auf korrekte REST-Verben mussten Security-Regeln und Tests gleichzeitig angepasst werden.
- In Zukunft wuerde ich zuerst eine klare Security-Matrix (Endpoint x Rolle x CSRF) festlegen und danach strikt testgetrieben implementieren.

### Aufwand vs. Ertrag

- Der Aufwand fuer Grundschutz (RBAC, CSRF, Hashing, Validation) ist moderat, bringt aber einen sehr hohen Sicherheitsgewinn.
- Der groesste Mehrwert entsteht durch systematische Tests: Sie machen Sicherheitsregressionen sofort sichtbar.
- Erweiterte Massnahmen (Rate Limiting, OIDC, Monitoring) brauchen mehr Zeit, sind fuer reale produktive Systeme aber oft lohnend.
