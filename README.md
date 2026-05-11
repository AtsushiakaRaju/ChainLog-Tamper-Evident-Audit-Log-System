# ChainLog — Tamper-Evident Audit Log System

A blockchain-inspired, cryptographically secure audit logging system built in Python. Every log entry is SHA-256 hashed and linked to the previous one — making any deletion, modification, or reordering instantly detectable.

---

## What It Does

ChainLog implements a **tamper-evident linked log** — the same core concept used in blockchain and enterprise audit systems — entirely from scratch in Python with zero external dependencies.

- **Add** timestamped log entries (LOGIN, LOGOUT, TRANSACTION, FILE_ACCESS, etc.)
- **Verify** the entire chain's integrity with a cryptographic two-pass check
- **Detect tampering** — any modification, deletion, or reordering breaks the chain
- **Persist** the log to disk as JSON between sessions

---

## Core Concepts

### Cryptographic Chaining
Each entry stores the **SHA-256 hash of the previous entry**. This creates a chain where:
- Deleting entry #2 breaks entry #3's `prev_hash` → detected
- Editing any field in entry #1 changes its hash → every downstream entry fails verification

### Two-Pass Integrity Check
When verifying, the system runs two independent checks per entry:

| Check | What It Catches |
|-------|----------------|
| Hash recomputation | Content modification (field edited) |
| Chain linkage check | Entry deletion or reordering |

### Genesis Block Pattern
The first entry uses a 64-zero sentinel (`"000...000"`) as its `prev_hash` — mirroring the genesis block pattern used in real blockchain systems.

---

## Demo

```
Options:
  1 → Add a log entry
  2 → Display all entries
  3 → Verify chain integrity
  4 → Delete an entry  (simulates attacker)
  5 → Modify an entry  (simulates attacker)
  6 → Exit
```

**Normal verification (intact chain):**
```
[✓] Entry #0 OK | LOGIN | 2025-05-10T10:23:01
[✓] Entry #1 OK | TRANSACTION | 2025-05-10T10:24:15
[✓] Entry #2 OK | LOGOUT | 2025-05-10T10:25:03
RESULT: All entries verified. Log is INTACT.
```

**After deleting Entry #1 (attacker simulation):**
```
[✓] Entry #0 OK | LOGIN | 2025-05-10T10:23:01
[✗] CHAIN BROKEN at Entry #1 — entry deleted or reordered!
      Expected prev: a3f1c9d2...
      Found prev   : 0000000000...
RESULT: TAMPERING DETECTED. Log has been compromised!
```

---

## Project Structure

```
ChainLog/
├── Tamper_evident_log.py          # Core implementation
├── secure_log.json    # Persisted log (auto-generated on first run)
└── README.md
```

---

## How to Run

```bash
# No dependencies — pure Python standard library
python Task_1.py
```

Requires Python 3.6+

---

## Key Implementation Details

- **`LogEntry.from_dict()`** — reconstructs entries from JSON *without* recomputing hashes, so stored (potentially tampered) hashes are preserved for comparison during verification
- **`__new__()` bypass** — uses `LogEntry.__new__(LogEntry)` to skip `__init__` during deserialization, a deliberate design choice to avoid masking tampering
- **Avalanche effect** — SHA-256 ensures a single character change in any field produces a completely different hash
- **Append-only design** — no update or delete method exposed; tampering must be done directly on the JSON file

---

## Concepts Demonstrated

- SHA-256 hashing (`hashlib`)
- Blockchain / linked-list data structures
- Tamper detection via cryptographic chaining
- Object serialization / deserialization (`json`)
- File persistence and integrity checking
- Simulated adversarial attacks (deletion, content modification)

---

## Use Cases (Real-World Relevance)

This pattern is used in production systems for:
- **Financial audit trails** — detecting unauthorized transaction edits
- **Medical record systems** — ensuring record immutability
- **Access control logs** — verifying no entries were scrubbed after a breach
- **Git's commit graph** — each commit stores the parent commit's SHA

---

## Author

**Harsha** 
