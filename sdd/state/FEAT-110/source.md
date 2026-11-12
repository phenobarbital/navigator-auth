---
kind: inline
jira_key: null
fetched_at: 2026-11-11T13:42:30Z
summary_oneline: "New 'navauth self upgrade' CLI command that applies SQL migrations from docs/migrations/ to navigator-auth tables"
---

# New command for database migrations

Any time a new column need to be added into navigator-auth tables (users, identities, etc) a migration SQL patch need to be created and executed manually, instead, using a new admin-based credentials, a CLI command can be used for running migrations, a simple "navauth self upgrade", will be used to check the existing migrations and compare with existing tables and applying the required changes, for example current auth.user_identities table is lack some new changes on my local, instead trying to find which changes I need to apply, create a docs/migrations/ folder with SQL-based changes, and run the changes over the tables using "navauth self upgrade" command.
