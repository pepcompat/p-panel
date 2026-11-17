# Rollback plan — 20261117102042_init

Initial schema. Rollback = drop the schema (dev/lab only, destroys all data):

```sql
DROP SCHEMA public CASCADE; CREATE SCHEMA public;
```

In production, never roll back the initial migration; restore from the pre-install backup instead.
