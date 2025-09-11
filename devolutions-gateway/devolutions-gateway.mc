; ----------------------------------------------------------------------
; Devolutions Gateway - Windows Event Log message definitions (.mc)
; English (0x409), French (0x40c), German (0x407)
; ----------------------------------------------------------------------

MessageIdTypedef=DWORD

SeverityNames=(
    Success=0x0:STATUS_SEVERITY_SUCCESS
    Informational=0x1:STATUS_SEVERITY_INFORMATIONAL
    Warning=0x2:STATUS_SEVERITY_WARNING
    Error=0x3:STATUS_SEVERITY_ERROR
)

FacilityNames=(
    Application=0x0:FACILITY_APPLICATION
)

LanguageNames=(
    English=0x409:MSG00409
    French=0x40c:MSG0040c
    German=0x407:MSG00407
)

; ======================================================================
; 1000-1099 Service / Lifecycle
; ======================================================================

MessageId=1000
SymbolicName=SERVICE_STARTED
Language=English
Service started. Context=%1 Version=%2
Language=French
Service démarré. Contexte=%1 Version=%2
Language=German
Dienst gestartet. Kontext=%1 Version=%2
.

MessageId=1001
SymbolicName=SERVICE_STOPPING
Language=English
Service stopping. Context=%1 Reason=%2
Language=French
Arrêt du service. Contexte=%1 Raison=%2
Language=German
Dienst wird gestoppt. Kontext=%1 Grund=%2
.

MessageId=1010
SymbolicName=CONFIG_INVALID
Language=English
Configuration invalid. Context=%1 Path=%2 Error=%3 Reason=%4
Language=French
Configuration invalide. Contexte=%1 Chemin=%2 Erreur=%3 Raison=%4
Language=German
Ungültige Konfiguration. Kontext=%1 Pfad=%2 Fehler=%3 Grund=%4
.

MessageId=1020
SymbolicName=START_FAILED
Language=English
Start failed. Context=%1 Cause=%2 Error=%3
Language=French
Échec du démarrage. Contexte=%1 Cause=%2 Erreur=%3
Language=German
Start fehlgeschlagen. Kontext=%1 Ursache=%2 Fehler=%3
.

MessageId=1030
SymbolicName=BOOT_STACKTRACE_WRITTEN
Language=English
Boot stacktrace written. Context=%1 Path=%2
Language=French
Trace d’amorçage écrite. Contexte=%1 Chemin=%2
Language=German
Boot-Stacktrace geschrieben. Kontext=%1 Pfad=%2
.

; ======================================================================
; 2000-2099 Listeners & Networking
; ======================================================================

MessageId=2000
SymbolicName=LISTENER_STARTED
Language=English
Listener started. Context=%1 Address=%2 Proto=%3
Language=French
Écouteur démarré. Contexte=%1 Adresse=%2 Protocole=%3
Language=German
Listener gestartet. Kontext=%1 Adresse=%2 Protokoll=%3
.

MessageId=2001
SymbolicName=LISTENER_BIND_FAILED
Language=English
Listener bind failed. Context=%1 Address=%2 Error=%3
Language=French
Échec de l’attachement de l’écouteur. Contexte=%1 Adresse=%2 Erreur=%3
Language=German
Listener-Bind fehlgeschlagen. Kontext=%1 Adresse=%2 Fehler=%3
.

MessageId=2002
SymbolicName=LISTENER_STOPPED
Language=English
Listener stopped. Context=%1 Address=%2 Reason=%3
Language=French
Écouteur arrêté. Contexte=%1 Adresse=%2 Raison=%3
Language=German
Listener gestoppt. Kontext=%1 Adresse=%2 Grund=%3
.

; ======================================================================
; 3000-3099 TLS / Certificates
; ======================================================================

MessageId=3000
SymbolicName=TLS_CONFIGURED
Language=English
TLS configured. Context=%1 Source=%2
Language=French
TLS configuré. Contexte=%1 Source=%2
Language=German
TLS konfiguriert. Kontext=%1 Quelle=%2
.

MessageId=3001
SymbolicName=TLS_VERIFY_STRICT_DISABLED
Language=English
TLS strict verification disabled. Context=%1 Mode=%2
Language=French
Vérification stricte TLS désactivée. Contexte=%1 Mode=%2
Language=German
Strikte TLS-Überprüfung deaktiviert. Kontext=%1 Modus=%2
.

MessageId=3002
SymbolicName=TLS_CERTIFICATE_REJECTED
Language=English
Certificate rejected. Context=%1 Subject=%2 Reason=%3
Language=French
Certificat rejeté. Contexte=%1 Sujet=%2 Raison=%3
Language=German
Zertifikat abgelehnt. Kontext=%1 Betreff=%2 Grund=%3
.

MessageId=3003
SymbolicName=SYSTEM_CERT_SELECTED
Language=English
System certificate selected. Context=%1 Thumbprint=%2 Subject=%3
Language=French
Certificat système sélectionné. Contexte=%1 Empreinte=%2 Sujet=%3
Language=German
Systemzertifikat ausgewählt. Kontext=%1 Fingerabdruck=%2 Betreff=%3
.

MessageId=3004
SymbolicName=TLS_KEY_LOAD_FAILED
Language=English
TLS key/cert load failed. Context=%1 Path=%2 Error=%3 Reason=%4
Language=French
Échec du chargement de la clé/cert TLS. Contexte=%1 Chemin=%2 Erreur=%3 Raison=%4
Language=German
TLS-Schlüssel/Zertifikat konnte nicht geladen werden. Kontext=%1 Pfad=%2 Fehler=%3 Grund=%4
.

MessageId=3005
SymbolicName=TLS_CERTIFICATE_NAME_MISMATCH
Language=English
TLS certificate name mismatch. Context=%1 Hostname=%2 Subject=%3 Reason=%4
Language=French
Nom du certificat TLS non concordant. Contexte=%1 Hôte=%2 Sujet=%3 Raison=%4
Language=German
TLS-Zertifikat-Namen stimmt nicht überein. Kontext=%1 Hostname=%2 Betreff=%3 Grund=%4
.

MessageId=3006
SymbolicName=TLS_NO_SUITABLE_CERTIFICATE
Language=English
No suitable certificate found. Context=%1 Error=%2 Issues=%3
Language=French
Aucun certificat approprié trouvé. Contexte=%1 Erreur=%2 Problèmes=%3
Language=German
Kein geeignetes Zertifikat gefunden. Kontext=%1 Fehler=%2 Probleme=%3
.

; ======================================================================
; 4000-4099 Sessions, Tokens & Recording
; ======================================================================

MessageId=4000
SymbolicName=SESSION_OPENED
Language=English
Session opened. Context=%1 Protocol=%2 Client=%3 Target=%4 TokenId=%5
Language=French
Session ouverte. Contexte=%1 Protocole=%2 Client=%3 Cible=%4 Jeton=%5
Language=German
Sitzung geöffnet. Kontext=%1 Protokoll=%2 Client=%3 Ziel=%4 Token=%5
.

MessageId=4001
SymbolicName=SESSION_CLOSED
Language=English
Session closed. Context=%1 DurationMs=%2 BytesTx=%3 BytesRx=%4 Outcome=%5
Language=French
Session fermée. Contexte=%1 DuréeMs=%2 OctetsTx=%3 OctetsRx=%4 Résultat=%5
Language=German
Sitzung geschlossen. Kontext=%1 DauerMs=%2 BytesTx=%3 BytesRx=%4 Ergebnis=%5
.

MessageId=4010
SymbolicName=TOKEN_PROVISIONED
Language=English
Token provisioned. Context=%1 TokenId=%2
Language=French
Jeton provisionné. Contexte=%1 Jeton=%2
Language=German
Token bereitgestellt. Kontext=%1 Token=%2
.

MessageId=4011
SymbolicName=TOKEN_REUSED
Language=English
Token reused. Context=%1 TokenId=%2 ReuseCount=%3
Language=French
Jeton réutilisé. Contexte=%1 Jeton=%2 Réutilisations=%3
Language=German
Token wiederverwendet. Kontext=%1 Token=%2 Anzahl=%3
.

MessageId=4012
SymbolicName=TOKEN_REUSE_LIMIT_EXCEEDED
Language=English
Token reuse limit exceeded. Context=%1 TokenId=%2 Limit=%3 Reason=%4
Language=French
Limite de réutilisation du jeton dépassée. Contexte=%1 Jeton=%2 Limite=%3 Raison=%4
Language=German
Token-Wiederverwendungsgrenze überschritten. Kontext=%1 Token=%2 Limit=%3 Grund=%4
.

MessageId=4030
SymbolicName=RECORDING_STARTED
Language=English
Recording started. Context=%1 Destination=%2
Language=French
Enregistrement démarré. Contexte=%1 Destination=%2
Language=German
Aufnahme gestartet. Kontext=%1 Ziel=%2
.

MessageId=4031
SymbolicName=RECORDING_STOPPED
Language=English
Recording stopped. Context=%1 Bytes=%2 Files=%3
Language=French
Enregistrement arrêté. Contexte=%1 Octets=%2 Fichiers=%3
Language=German
Aufnahme gestoppt. Kontext=%1 Bytes=%2 Dateien=%3
.

MessageId=4032
SymbolicName=RECORDING_ERROR
Language=English
Recording error. Context=%1 Path=%2 Error=%3
Language=French
Erreur d’enregistrement. Contexte=%1 Chemin=%2 Erreur=%3
Language=German
Aufnahmefehler. Kontext=%1 Pfad=%2 Fehler=%3
.

; ======================================================================
; 5000-5099 Authentication / Authorization
; ======================================================================

MessageId=5001
SymbolicName=JWT_REJECTED
Language=English
JWT rejected. Context=%1 ReasonCode=%2 Reason=%3
Language=French
JWT rejeté. Contexte=%1 CodeRaison=%2 Raison=%3
Language=German
JWT abgelehnt. Kontext=%1 GrundCode=%2 Grund=%3
.

MessageId=5002
SymbolicName=JWT_ANOMALY
Language=English
JWT anomaly. Context=%1 Issuer=%2 Audience=%3 Kid=%4 Kind=%5 Detail=%6
Language=French
Anomalie JWT. Contexte=%1 Émetteur=%2 Audience=%3 Kid=%4 Type=%5 Détail=%6
Language=German
JWT-Anomalie. Kontext=%1 Aussteller=%2 Audience=%3 Kid=%4 Typ=%5 Detail=%6
.

MessageId=5010
SymbolicName=AUTHORIZATION_DENIED
Language=English
Authorization denied. Context=%1 Subject=%2 Action=%3 Resource=%4 Rule=%5 Reason=%6
Language=French
Autorisation refusée. Contexte=%1 Sujet=%2 Action=%3 Ressource=%4 Règle=%5 Raison=%6
Language=German
Autorisierung verweigert. Kontext=%1 Subjekt=%2 Aktion=%3 Ressource=%4 Regel=%5 Grund=%6
.

MessageId=5090
SymbolicName=AUTH_SUMMARY
Language=English
Auth summary. Context=%1 IntervalSec=%2 JwtOk=%3 JwtRejected=%4 Denied=%5 ByReason=%6
Language=French
Résumé d’auth. Contexte=%1 IntervalSec=%2 JwtOk=%3 JwtRejeté=%4 Refusé=%5 ParRaison=%6
Language=German
Auth-Zusammenfassung. Kontext=%1 IntervallSek=%2 JwtOk=%3 JwtAbgelehnt=%4 Verweigert=%5 NachGrund=%6
.

; ======================================================================
; 6000-6099 Agent Integration
; ======================================================================

MessageId=6000
SymbolicName=USER_SESSION_PROCESS_STARTED
Language=English
User session process started. Context=%1 SessionId=%2 Kind=%3 Exe=%4
Language=French
Processus de session utilisateur démarré. Contexte=%1 SessionId=%2 Type=%3 Exe=%4
Language=German
Benutzersitzungsprozess gestartet. Kontext=%1 SessionId=%2 Typ=%3 Exe=%4
.

MessageId=6001
SymbolicName=USER_SESSION_PROCESS_TERMINATED
Language=English
User session process terminated. Context=%1 SessionId=%2 ExitCode=%3 By=%4
Language=French
Processus de session utilisateur terminé. Contexte=%1 SessionId=%2 CodeSortie=%3 Par=%4
Language=German
Benutzersitzungsprozess beendet. Kontext=%1 SessionId=%2 ExitCode=%3 Durch=%4
.

MessageId=6010
SymbolicName=UPDATER_TASK_ENABLED
Language=English
Updater task enabled. Context=%1
Language=French
Tâche de mise à jour activée. Contexte=%1
Language=German
Update-Aufgabe aktiviert. Kontext=%1
.

MessageId=6011
SymbolicName=UPDATER_ERROR
Language=English
Updater error. Context=%1 Step=%2 Error=%3
Language=French
Erreur de mise à jour. Contexte=%1 Étape=%2 Erreur=%3
Language=German
Update-Fehler. Kontext=%1 Schritt=%2 Fehler=%3
.

MessageId=6020
SymbolicName=PEDM_ENABLED
Language=English
PEDM enabled. Context=%1
Language=French
PEDM activé. Contexte=%1
Language=German
PEDM aktiviert. Kontext=%1
.

; ======================================================================
; 7000-7099 Health
; ======================================================================

MessageId=7010
SymbolicName=RECORDING_STORAGE_LOW
Language=English
Recording storage low. Context=%1 RemainingBytes=%2 ThresholdBytes=%3
Language=French
Espace d’enregistrement faible. Contexte=%1 OctetsRestants=%2 Seuil=%3
Language=German
Aufnahmespeicher niedrig. Kontext=%1 VerbleibendeBytes=%2 Schwelle=%3
.

; ======================================================================
; 9000-9099 Diagnostics
; ======================================================================

MessageId=9001
SymbolicName=DEBUG_OPTIONS_ENABLED
Language=English
Debug options enabled. Context=%1 Options=%2
Language=French
Options de débogage activées. Contexte=%1 Options=%2
Language=German
Debug-Optionen aktiviert. Kontext=%1 Optionen=%2
.

MessageId=9002
SymbolicName=XMF_NOT_FOUND
Language=English
XMF not found. Context=%1 Path=%2 Error=%3
Language=French
XMF introuvable. Contexte=%1 Chemin=%2 Erreur=%3
Language=German
XMF nicht gefunden. Kontext=%1 Pfad=%2 Fehler=%3
.
