# SQL Safety Proxy v0.6.0a1

## Phase 1: MySQL/MariaDB adapter foundation

- Registers MySQL and MariaDB as one adapter family.
- Adds MySQL packet framing and synthetic error-packet helpers.
- Adds a least-privilege `aiomysql` impact estimator.
- Keeps the wire runtime and binary prepared statements disabled until the
  next validation gate.
