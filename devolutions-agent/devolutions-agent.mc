; Devolutions Agent Windows Event Log message definitions.
; Scope: the codes declared in the `agent-sysevent-codes` crate, and only those.
; Codes shared with Devolutions Gateway are duplicated here, so the Agent never refers to a
; message it does not carry, and Gateway-only translations are absent.
; Languages: English, French, German.

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

; 1000-1099 Service / Lifecycle

MessageId=1000
SymbolicName=SERVICE_STARTED
Language=English
Service started. Context=%1 Version=%2
.
Language=French
Service démarré. Contexte=%1 Version=%2
.
Language=German
Dienst gestartet. Kontext=%1 Version=%2
.

MessageId=1001
SymbolicName=SERVICE_STOPPING
Language=English
Service stopping. Context=%1 Reason=%2
.
Language=French
Arrêt du service. Contexte=%1 Raison=%2
.
Language=German
Dienst wird gestoppt. Kontext=%1 Grund=%2
.

MessageId=1010
SymbolicName=CONFIG_INVALID
Language=English
Configuration invalid. Context=%1 Path=%2 Error=%3 Reason=%4
.
Language=French
Configuration invalide. Contexte=%1 Chemin=%2 Erreur=%3 Raison=%4
.
Language=German
Ungültige Konfiguration. Kontext=%1 Pfad=%2 Fehler=%3 Grund=%4
.

MessageId=1020
SymbolicName=START_FAILED
Language=English
Start failed. Context=%1 Cause=%2 Error=%3
.
Language=French
Échec du démarrage. Contexte=%1 Cause=%2 Erreur=%3
.
Language=German
Start fehlgeschlagen. Kontext=%1 Ursache=%2 Fehler=%3
.

MessageId=1030
SymbolicName=BOOT_STACKTRACE_WRITTEN
Language=English
Boot stacktrace written. Context=%1 Path=%2
.
Language=French
Trace d’amorçage écrite. Contexte=%1 Chemin=%2
.
Language=German
Boot-Stacktrace geschrieben. Kontext=%1 Pfad=%2
.

; 6000-6099 User Sessions

MessageId=6000
SymbolicName=USER_SESSION_PROCESS_STARTED
Language=English
User session process started. Context=%1 SessionId=%2 Kind=%3 Exe=%4
.
Language=French
Processus de session utilisateur démarré. Contexte=%1 SessionId=%2 Type=%3 Exe=%4
.
Language=German
Benutzersitzungsprozess gestartet. Kontext=%1 SessionId=%2 Typ=%3 Exe=%4
.

MessageId=6001
SymbolicName=USER_SESSION_PROCESS_TERMINATED
Language=English
User session process terminated. Context=%1 SessionId=%2 ExitCode=%3 By=%4
.
Language=French
Processus de session utilisateur terminé. Contexte=%1 SessionId=%2 CodeSortie=%3 Par=%4
.
Language=German
Benutzersitzungsprozess beendet. Kontext=%1 SessionId=%2 ExitCode=%3 Durch=%4
.

; 6100-6199 Updater

MessageId=6100
SymbolicName=UPDATER_TASK_ENABLED
Language=English
Updater task enabled. Context=%1
.
Language=French
Tâche de mise à jour activée. Contexte=%1
.
Language=German
Update-Aufgabe aktiviert. Kontext=%1
.

MessageId=6101
SymbolicName=UPDATER_ERROR
Language=English
Updater error. Context=%1 Step=%2 Error=%3
.
Language=French
Erreur de mise à jour. Contexte=%1 Étape=%2 Erreur=%3
.
Language=German
Update-Fehler. Kontext=%1 Schritt=%2 Fehler=%3
.

; 6200-6299 PEDM

MessageId=6200
SymbolicName=PEDM_ENABLED
Language=English
PEDM enabled. Context=%1
.
Language=French
PEDM activé. Contexte=%1
.
Language=German
PEDM aktiviert. Kontext=%1
.

; 8000-8099 Package Broker / Policy Management

MessageId=8000
SymbolicName=POLICY_WRITE_ATTEMPTED
Language=English
Policy management write attempted. Context=%1 ActorSid=%2 ActorExe=%3 Intent=%4 Path=%5
.
Language=French
Tentative d’écriture de politique. Contexte=%1 SidActeur=%2 ExeActeur=%3 Intention=%4 Chemin=%5
.
Language=German
Richtlinien-Schreibvorgang versucht. Kontext=%1 AkteurSid=%2 AkteurExe=%3 Absicht=%4 Pfad=%5
.

MessageId=8001
SymbolicName=POLICY_WRITE_DENIED
Language=English
Policy management write denied. Context=%1 ActorSid=%2 ActorExe=%3 Intent=%4 Path=%5 Reason=%6
.
Language=French
Écriture de politique refusée. Contexte=%1 SidActeur=%2 ExeActeur=%3 Intention=%4 Chemin=%5 Raison=%6
.
Language=German
Richtlinien-Schreibvorgang verweigert. Kontext=%1 AkteurSid=%2 AkteurExe=%3 Absicht=%4 Pfad=%5 Grund=%6
.

MessageId=8002
SymbolicName=POLICY_CREATE_FAILED
Language=English
Policy creation failed. Context=%1 ActorSid=%2 ActorExe=%3 Intent=%4 Path=%5 Operation=%6 Outcome=%7 Reason=%8
.
Language=French
Échec de la création de politique. Contexte=%1 SidActeur=%2 ExeActeur=%3 Intention=%4 Chemin=%5 Opération=%6 Résultat=%7 Raison=%8
.
Language=German
Richtlinienerstellung fehlgeschlagen. Kontext=%1 AkteurSid=%2 AkteurExe=%3 Absicht=%4 Pfad=%5 Vorgang=%6 Ergebnis=%7 Grund=%8
.

MessageId=8003
SymbolicName=POLICY_CREATE_SUCCEEDED
Language=English
Policy creation succeeded. Context=%1 ActorSid=%2 ActorExe=%3 Path=%4 OldId=%5 OldRevision=%6 NewId=%7 NewRevision=%8 Intent=%9 Operation=%10 Outcome=%11
.
Language=French
Création de politique réussie. Contexte=%1 SidActeur=%2 ExeActeur=%3 Chemin=%4 AncienId=%5 AncienneRévision=%6 NouvelId=%7 NouvelleRévision=%8 Intention=%9 Opération=%10 Résultat=%11
.
Language=German
Richtlinie erfolgreich erstellt. Kontext=%1 AkteurSid=%2 AkteurExe=%3 Pfad=%4 AlteId=%5 AlteRevision=%6 NeueId=%7 NeueRevision=%8 Absicht=%9 Vorgang=%10 Ergebnis=%11
.

MessageId=8004
SymbolicName=POLICY_CHANGE_FAILED
Language=English
Policy change failed. Context=%1 ActorSid=%2 ActorExe=%3 Intent=%4 Path=%5 Operation=%6 Outcome=%7 Reason=%8
.
Language=French
Échec de la modification de politique. Contexte=%1 SidActeur=%2 ExeActeur=%3 Intention=%4 Chemin=%5 Opération=%6 Résultat=%7 Raison=%8
.
Language=German
Richtlinienänderung fehlgeschlagen. Kontext=%1 AkteurSid=%2 AkteurExe=%3 Absicht=%4 Pfad=%5 Vorgang=%6 Ergebnis=%7 Grund=%8
.

MessageId=8005
SymbolicName=POLICY_CHANGE_SUCCEEDED
Language=English
Policy change succeeded. Context=%1 ActorSid=%2 ActorExe=%3 Path=%4 OldId=%5 OldRevision=%6 NewId=%7 NewRevision=%8 Intent=%9 Operation=%10 Outcome=%11
.
Language=French
Modification de politique réussie. Contexte=%1 SidActeur=%2 ExeActeur=%3 Chemin=%4 AncienId=%5 AncienneRévision=%6 NouvelId=%7 NouvelleRévision=%8 Intention=%9 Opération=%10 Résultat=%11
.
Language=German
Richtlinie erfolgreich geändert. Kontext=%1 AkteurSid=%2 AkteurExe=%3 Pfad=%4 AlteId=%5 AlteRevision=%6 NeueId=%7 NeueRevision=%8 Absicht=%9 Vorgang=%10 Ergebnis=%11
.

MessageId=8010
SymbolicName=POLICY_EXTERNAL_CHANGE_APPLIED
Language=English
External policy change applied. Context=%1 Path=%2 NewId=%3 NewRevision=%4
.
Language=French
Modification externe de la politique appliquée. Contexte=%1 Chemin=%2 NouvelId=%3 NouvelleRévision=%4
.
Language=German
Externe Richtlinienänderung angewendet. Kontext=%1 Pfad=%2 NeueId=%3 NeueRevision=%4
.

MessageId=8011
SymbolicName=POLICY_EXTERNAL_CHANGE_REJECTED
Language=English
External policy change rejected. Context=%1 Path=%2 Reason=%3
.
Language=French
Modification externe de la politique rejetée. Contexte=%1 Chemin=%2 Raison=%3
.
Language=German
Externe Richtlinienänderung abgelehnt. Kontext=%1 Pfad=%2 Grund=%3
.

MessageId=8090
SymbolicName=POLICY_WRITE_DENIED_SUMMARY
Language=English
Policy management write denials summarized. Context=%1 ActorSid=%2 Intent=%3 Reason=%4 Suppressed=%5 IntervalSec=%6
.
Language=French
Résumé des écritures de politique refusées. Contexte=%1 SidActeur=%2 Intention=%3 Raison=%4 Supprimés=%5 IntervalSec=%6
.
Language=German
Zusammenfassung verweigerter Richtlinien-Schreibvorgänge. Kontext=%1 AkteurSid=%2 Absicht=%3 Grund=%4 Unterdrückt=%5 IntervallSek=%6
.
