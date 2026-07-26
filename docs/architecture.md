# Architecture

SQL Safety Proxy currently consists of five layers:

1. **PostgreSQL protocol framing** — reads startup, simple-query, and extended-query messages.
2. **Connection state** — remembers prepared statements, portals, and bound values.
3. **Risk classification** — parses SQL into an AST and identifies mutation risk.
4. **Impact estimation** — runs eligible read-only preview queries through a separate connection.
5. **Confirmation provider** — asks a human to approve or block execution.

The target long-term structure is a database-independent policy core surrounded by database-specific protocol and estimation adapters.
