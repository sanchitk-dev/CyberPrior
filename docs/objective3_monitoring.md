# Objective 3: Monitoring, History, and Alerts

## Implemented prototype

The local web app provides a manual snapshot-check workflow at **Monitoring & alerts**. Each check stores the current finalized prioritized dataset in the local SQLite database, records its risk-level counts, and compares each asset record with the preceding check. The page shows the latest eight risk-mix snapshots, recent change alerts, and a current critical/high attention queue.

Alerts are created when a record:

* becomes newly listed in CISA KEV;
* moves to a higher residual-risk level;
* increases by at least 10 residual-risk points; or
* moves at least 25 places upward in the suggested resolve order.

The first check is a baseline and does not generate change alerts. Users can acknowledge alerts; acknowledgement is stored per local account.

## Scope and limitations

Checks are manual and compare the dataset files loaded by the app. They do not scan devices, watch networks, refresh NVD/EPSS/CISA KEV, or run on a schedule. Regenerate the processed project files and restart the app before checking a refreshed dataset. Asset details are synthetic project scenarios. This feature demonstrates snapshot history and change detection; it is not a production monitoring service.
