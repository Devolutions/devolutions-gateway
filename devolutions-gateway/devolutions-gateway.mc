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
Service started. Version=%1
Language=French
Service démarré. Version=%1
Language=German
Dienst gestartet. Version=%1
.

MessageId=1001
SymbolicName=SERVICE_STOPPING
Language=English
Service stopping. Reason=%1
Language=French
Arrêt du service. Raison=%1
Language=German
Dienst wird gestoppt. Grund=%1
.

MessageId=1010
SymbolicName=CONFIG_INVALID
Language=English
Configuration invalid. Path=%1 Error=%2 Reason=%3
Language=French
Configuration invalide. Chemin=%1 Erreur=%2 Raison=%3
Language=German
Ungültige Konfiguration. Pfad=%1 Fehler=%2 Grund=%3
.

MessageId=1020
SymbolicName=START_FAILED
Language=English
Start failed. Cause=%1 Error=%2
Language=French
Échec du démarrage. Cause=%1 Erreur=%2
Language=German
Start fehlgeschlagen. Ursache=%1 Fehler=%2
.

MessageId=1030
SymbolicName=BOOT_STACKTRACE_WRITTEN
Language=English
Boot stacktrace written. Path=%1
Language=French
Trace d’amorçage écrite. Chemin=%1
Language=German
Boot-Stacktrace geschrieben. Pfad=%1
.

; ======================================================================
; 2000-2099 Listeners & Networking
; ======================================================================

MessageId=2000
SymbolicName=LISTENER_STARTED
Language=English
Listener started. Address=%1 Proto=%2
Language=French
Écouteur démarré. Adresse=%1 Protocole=%2
Language=German
Listener gestartet. Adresse=%1 Protokoll=%2
.

MessageId=2001
SymbolicName=LISTENER_BIND_FAILED
Language=English
Listener bind failed. Address=%1 Error=%2
Language=French
Échec de l’attachement de l’écouteur. Adresse=%1 Erreur=%2
Language=German
Listener-Bind fehlgeschlagen. Adresse=%1 Fehler=%2
.

MessageId=2002
SymbolicName=LISTENER_STOPPED
Language=English
Listener stopped. Address=%1 Reason=%2
Language=French
Écouteur arrêté. Adresse=%1 Raison=%2
Language=German
Listener gestoppt. Adresse=%1 Grund=%2
.

; ======================================================================
; 3000-3099 TLS / Certificates
; ======================================================================

MessageId=3000
SymbolicName=TLS_CONFIGURED
Language=English
TLS configured. Source=%1
Language=French
TLS configuré. Source=%1
Language=German
TLS konfiguriert. Quelle=%1
.

MessageId=3001
SymbolicName=TLS_VERIFY_STRICT_DISABLED
Language=English
TLS strict verification disabled. Mode=%1
Language=French
Vérification stricte TLS désactivée. Mode=%1
Language=German
Strikte TLS-Überprüfung deaktiviert. Modus=%1
.

MessageId=3002
SymbolicName=TLS_CERTIFICATE_REJECTED
Language=English
Certificate rejected. Subject=%1 Reason=%2
Language=French
Certificat rejeté. Sujet=%1 Raison=%2
Language=German
Zertifikat abgelehnt. Betreff=%1 Grund=%2
.

MessageId=3003
SymbolicName=SYSTEM_CERT_SELECTED
Language=English
System certificate selected. Thumbprint=%1 Subject=%2
Language=French
Certificat système sélectionné. Empreinte=%1 Sujet=%2
Language=German
Systemzertifikat ausgewählt. Fingerabdruck=%1 Betreff=%2
.

MessageId=3004
SymbolicName=TLS_KEY_LOAD_FAILED
Language=English
TLS key/cert load failed. Path=%1 Error=%2 Reason=%3
Language=French
Échec du chargement de la clé/cert TLS. Chemin=%1 Erreur=%2 Raison=%3
Language=German
TLS-Schlüssel/Zertifikat konnte nicht geladen werden. Pfad=%1 Fehler=%2 Grund=%3
.

MessageId=3005
SymbolicName=TLS_CERTIFICATE_NAME_MISMATCH
Language=English
TLS certificate name mismatch. Hostname=%1 Subject=%2 Reason=%3
Language=French
Nom du certificat TLS non concordant. Hôte=%1 Sujet=%2 Raison=%3
Language=German
TLS-Zertifikat-Namen stimmt nicht überein. Hostname=%1 Betreff=%2 Grund=%3
.

MessageId=3006
SymbolicName=TLS_NO_SUITABLE_CERTIFICATE
Language=English
No suitable certificate found. Error=%1 Issues=%2
Language=French
Aucun certificat approprié trouvé. Erreur=%1 Problèmes=%2
Language=German
Kein geeignetes Zertifikat gefunden. Fehler=%1 Probleme=%2
.

; ======================================================================
; 4000-4099 Sessions, Tokens & Recording
; ======================================================================

MessageId=4000
SymbolicName=SESSION_OPENED
Language=English
Session opened. Protocol=%1 Client=%2 Target=%3 TokenId=%4
Language=French
Session ouverte. Protocole=%1 Client=%2 Cible=%3 Jeton=%4
Language=German
Sitzung geöffnet. Protokoll=%1 Client=%2 Ziel=%3 Token=%4
.

MessageId=4001
SymbolicName=SESSION_CLOSED
Language=English
Session closed. DurationMs=%1 BytesTx=%2 BytesRx=%3 Outcome=%4
Language=French
Session fermée. DuréeMs=%1 OctetsTx=%2 OctetsRx=%3 Résultat=%4
Language=German
Sitzung geschlossen. DauerMs=%1 BytesTx=%2 BytesRx=%3 Ergebnis=%4
.

MessageId=4010
SymbolicName=TOKEN_PROVISIONED
Language=English
Token provisioned. TokenId=%1
Language=French
Jeton provisionné. Jeton=%1
Language=German
Token bereitgestellt. Token=%1
.

MessageId=4011
SymbolicName=TOKEN_REUSED
Language=English
Token reused. TokenId=%1 ReuseCount=%2
Language=French
Jeton réutilisé. Jeton=%1 Réutilisations=%2
Language=German
Token wiederverwendet. Token=%1 Anzahl=%2
.

MessageId=4012
SymbolicName=TOKEN_REUSE_LIMIT_EXCEEDED
Language=English
Token reuse limit exceeded. TokenId=%1 Limit=%2 Reason=%3
Language=French
Limite de réutilisation du jeton dépassée. Jeton=%1 Limite=%2 Raison=%3
Language=German
Token-Wiederverwendungsgrenze überschritten. Token=%1 Limit=%2 Grund=%3
.

MessageId=4030
SymbolicName=RECORDING_STARTED
Language=English
Recording started. Destination=%1
Language=French
Enregistrement démarré. Destination=%1
Language=German
Aufnahme gestartet. Ziel=%1
.

MessageId=4031
SymbolicName=RECORDING_STOPPED
Language=English
Recording stopped. Bytes=%1 Files=%2
Language=French
Enregistrement arrêté. Octets=%1 Fichiers=%2
Language=German
Aufnahme gestoppt. Bytes=%1 Dateien=%2
.

MessageId=4032
SymbolicName=RECORDING_ERROR
Language=English
Recording error. Path=%1 Error=%2
Language=French
Erreur d’enregistrement. Chemin=%1 Erreur=%2
Language=German
Aufnahmefehler. Pfad=%1 Fehler=%2
.

; ======================================================================
; 5000-5099 Authentication / Authorization
; ======================================================================

MessageId=5001
SymbolicName=JWT_REJECTED
Language=English
JWT rejected. ReasonCode=%1 Reason=%2
Language=French
JWT rejeté. CodeRaison=%1 Raison=%2
Language=German
JWT abgelehnt. GrundCode=%1 Grund=%2
.

MessageId=5002
SymbolicName=JWT_ANOMALY
Language=English
JWT anomaly. Issuer=%1 Audience=%2 Kid=%3 Kind=%4 Detail=%5
Language=French
Anomalie JWT. Émetteur=%1 Audience=%2 Kid=%3 Type=%4 Détail=%5
Language=German
JWT-Anomalie. Aussteller=%1 Audience=%2 Kid=%3 Typ=%4 Detail=%5
.

MessageId=5010
SymbolicName=AUTHORIZATION_DENIED
Language=English
Authorization denied. Subject=%1 Action=%2 Resource=%3 Rule=%4 Reason=%5
Language=French
Autorisation refusée. Sujet=%1 Action=%2 Ressource=%3 Règle=%4 Raison=%5
Language=German
Autorisierung verweigert. Subjekt=%1 Aktion=%2 Ressource=%3 Regel=%4 Grund=%5
.

MessageId=5090
SymbolicName=AUTH_SUMMARY
Language=English
Auth summary. IntervalSec=%1 JwtOk=%2 JwtRejected=%3 Denied=%4 ByReason=%5
Language=French
Résumé d’auth. IntervalSec=%1 JwtOk=%2 JwtRejeté=%3 Refusé=%4 ParRaison=%5
Language=German
Auth-Zusammenfassung. IntervallSek=%1 JwtOk=%2 JwtAbgelehnt=%3 Verweigert=%4 NachGrund=%5
.

; ======================================================================
; 6000-6099 Agent Integration
; ======================================================================

MessageId=6000
SymbolicName=USER_SESSION_PROCESS_STARTED
Language=English
User session process started. SessionId=%1 Kind=%2 Exe=%3
Language=French
Processus de session utilisateur démarré. SessionId=%1 Type=%2 Exe=%3
Language=German
Benutzersitzungsprozess gestartet. SessionId=%1 Typ=%2 Exe=%3
.

MessageId=6001
SymbolicName=USER_SESSION_PROCESS_TERMINATED
Language=English
User session process terminated. SessionId=%1 ExitCode=%2 By=%3
Language=French
Processus de session utilisateur terminé. SessionId=%1 CodeSortie=%2 Par=%3
Language=German
Benutzersitzungsprozess beendet. SessionId=%1 ExitCode=%2 Durch=%3
.

MessageId=6010
SymbolicName=UPDATER_TASK_ENABLED
Language=English
Updater task enabled.
Language=French
Tâche de mise à jour activée.
Language=German
Update-Aufgabe aktiviert.
.

MessageId=6011
SymbolicName=UPDATER_ERROR
Language=English
Updater error. Step=%1 Error=%2
Language=French
Erreur de mise à jour. Étape=%1 Erreur=%2
Language=German
Update-Fehler. Schritt=%1 Fehler=%2
.

MessageId=6020
SymbolicName=PEDM_ENABLED
Language=English
PEDM enabled.
Language=French
PEDM activé.
Language=German
PEDM aktiviert.
.

; ======================================================================
; 7000-7099 Health
; ======================================================================

MessageId=7010
SymbolicName=RECORDING_STORAGE_LOW
Language=English
Recording storage low. RemainingBytes=%1 ThresholdBytes=%2
Language=French
Espace d’enregistrement faible. OctetsRestants=%1 Seuil=%2
Language=German
Aufnahmespeicher niedrig. VerbleibendeBytes=%1 Schwelle=%2
.

; ======================================================================
; 9000-9099 Diagnostics
; ======================================================================

MessageId=9001
SymbolicName=DEBUG_OPTIONS_ENABLED
Language=English
Debug options enabled. Options=%1
Language=French
Options de débogage activées. Options=%1
Language=German
Debug-Optionen aktiviert. Optionen=%1
.

MessageId=9002
SymbolicName=XMF_NOT_FOUND
Language=English
XMF not found. Path=%1 Error=%2
Language=French
XMF introuvable. Chemin=%1 Erreur=%2
Language=German
XMF nicht gefunden. Pfad=%1 Fehler=%2
.
