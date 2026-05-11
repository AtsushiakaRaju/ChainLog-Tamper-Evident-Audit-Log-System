import hashlib
import json
import os
from datetime import datetime


def compute_hash(data: str) -> str:
    """SHA-256 hash of any string — the cryptographic backbone of the entire chain."""
    return hashlib.sha256(data.encode()).hexdigest()


class LogEntry:
    """
    A single node in the tamper-evident chain.
    Each entry stores the previous entry's hash, forming a linked structure
    identical in concept to a blockchain block.
    """

    def __init__(self, index, timestamp, event_type, description, prev_hash):
        self.index = index
        self.timestamp = timestamp
        self.event_type = event_type
        self.description = description
        self.prev_hash = prev_hash
        self.hash = self._compute_own_hash()  # computed at creation, never stored separately

    def _compute_own_hash(self) -> str:
        """
        Hashes all 5 fields concatenated — any single character change
        in any field produces a completely different hash (avalanche effect).
        """
        raw = f"{self.index}{self.timestamp}{self.event_type}{self.description}{self.prev_hash}"
        return compute_hash(raw)

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "prev_hash": self.prev_hash,
            "hash": self.hash
        }

    @staticmethod
    def from_dict(data: dict):
        """
        Reconstructs a LogEntry from persisted JSON WITHOUT recomputing the hash.
        This is intentional — preserves the stored hash so verify_chain() can
        compare it against the freshly recomputed expected hash.
        """
        entry = LogEntry.__new__(LogEntry)   # bypasses __init__ to avoid re-hashing
        entry.index       = data["index"]
        entry.timestamp   = data["timestamp"]
        entry.event_type  = data["event_type"]
        entry.description = data["description"]
        entry.prev_hash   = data["prev_hash"]
        entry.hash        = data["hash"]     # loaded as-is — may be tampered
        return entry


class TamperEvidentLog:
    """
    Append-only log where each entry is cryptographically linked to the previous.
    Deletion or modification of any entry breaks the chain and is detectable on verify.
    """

    FIRST_HASH = "0" * 64   # genesis sentinel — the "prev_hash" of entry #0
    LOG_FILE = "secure_log.json"

    def __init__(self):
        self.entries = []
        self._load_from_file()

    def add_entry(self, event_type: str, description: str):
        """
        Appends a new entry whose prev_hash points to the tail of the current chain.
        This is what makes deletion detectable — removing any entry breaks the link.
        """
        index = len(self.entries)
        prev_hash = self.FIRST_HASH if index == 0 else self.entries[-1].hash

        entry = LogEntry(index, datetime.now().isoformat(), event_type, description, prev_hash)
        self.entries.append(entry)
        self._save_to_file()

        print(f"[+] Entry #{index} added | Type: {event_type} | Hash: {entry.hash[:16]}...")
        return entry

    def verify_chain(self) -> bool:
        """
        Two-pass integrity check per entry:
          1. Recompute hash from fields → detects content modification (option 5)
          2. Check prev_hash linkage   → detects deletion / reordering (option 4)
        Both checks must pass for the log to be considered INTACT.
        """
        print("\n" + "="*60)
        print("  INTEGRITY VERIFICATION REPORT")
        print("="*60)

        if not self.entries:
            print("  [!] Log is empty. Nothing to verify.")
            return True

        all_valid = True

        for i, entry in enumerate(self.entries):

            # Check 1: content integrity
            expected_hash = LogEntry(
                entry.index, entry.timestamp,
                entry.event_type, entry.description, entry.prev_hash
            ).hash

            if entry.hash != expected_hash:
                print(f"  [✗] TAMPERED! Entry #{i} — content has been modified!")
                print(f"      Stored hash : {entry.hash[:32]}...")
                print(f"      Expected    : {expected_hash[:32]}...")
                all_valid = False
                continue

            # Check 2: chain linkage
            expected_prev = self.FIRST_HASH if i == 0 else self.entries[i - 1].hash

            if entry.prev_hash != expected_prev:
                print(f"  [✗] CHAIN BROKEN at Entry #{i} — entry deleted or reordered!")
                print(f"      Expected prev: {expected_prev[:32]}...")
                print(f"      Found prev   : {entry.prev_hash[:32]}...")
                all_valid = False
            else:
                print(f"  [✓] Entry #{i} OK | {entry.event_type} | {entry.timestamp}")

        print("="*60)
        print("  RESULT: " + ("All entries verified. Log is INTACT." if all_valid
                               else "TAMPERING DETECTED. Log has been compromised!"))
        print("="*60 + "\n")
        return all_valid

    def display_log(self):
        print("\n" + "="*60)
        print("  CURRENT LOG ENTRIES")
        print("="*60)
        if not self.entries:
            print("  (No entries yet)")
        for entry in self.entries:
            print(f"\n  Entry #{entry.index}")
            print(f"  Time      : {entry.timestamp}")
            print(f"  Event     : {entry.event_type}")
            print(f"  Details   : {entry.description}")
            print(f"  Prev Hash : {entry.prev_hash[:24]}...")
            print(f"  Own Hash  : {entry.hash[:24]}...")
            print(f"  {'-'*50}")
        print("="*60 + "\n")

    def _save_to_file(self):
        with open(self.LOG_FILE, "w") as f:
            json.dump([e.to_dict() for e in self.entries], f, indent=2)

    def _load_from_file(self):
        
        #Loads entries with their stored hashes intact (via from_dict).
        #Does NOT recompute hashes on load — that would mask tampering.
        
        if os.path.exists(self.LOG_FILE):
            with open(self.LOG_FILE, "r") as f:
                content = f.read().strip()
                if not content:
                    print("[*] Log file is empty. Starting fresh.")
                    return
                self.entries = [LogEntry.from_dict(d) for d in json.loads(content)]
            print(f"[*] Loaded {len(self.entries)} existing log entries.")
        else:
            print("[*] No existing log found. Starting fresh.")


def run_demo():
    log = TamperEvidentLog()

    print("\n" + "="*50)
    print("  TAMPER-EVIDENT LOGGING SYSTEM")
    print("="*50)

    while True:
        print("\nOptions:")
        print("  1 → Add a log entry")
        print("  2 → Display all entries")
        print("  3 → Verify chain integrity")
        print("  4 → Delete an entry  (simulates attacker)")
        print("  5 → Modify an entry  (simulates attacker)")
        print("  6 → Exit")

        choice = input("\nEnter choice: ").strip()

        if choice == "1":
            event_type  = input("Event type (LOGIN/LOGOUT/TRANSACTION/FILE_ACCESS): ").strip().upper()
            description = input("Description: ").strip()
            log.add_entry(event_type, description)

        elif choice == "2":
            log.display_log()

        elif choice == "3":
            log.verify_chain()

        elif choice == "4":
            # Simulates an attacker deleting evidence — breaks prev_hash linkage
            if not log.entries:
                print("No entries to delete.")
                continue
            log.display_log()
            try:
                index = int(input("Enter entry number to delete: ").strip())
                if index < 0 or index >= len(log.entries):
                    print("Invalid entry number.")
                    continue
            except ValueError:
                print("Please enter a valid number.")
                continue

            deleted = log.entries.pop(index)
            log._save_to_file()
            print(f"\n[!] Entry #{index} ('{deleted.event_type}') deleted from chain.")
            print("[!] Run option 3 to see the tamper detection trigger.")

        elif choice == "5":
            # Simulates an attacker editing a field — hash mismatch on verify
            if not log.entries:
                print("No entries to modify.")
                continue
            log.display_log()
            try:
                index = int(input("Enter entry number to modify: ").strip())
                if index < 0 or index >= len(log.entries):
                    print("Invalid entry number.")
                    continue
            except ValueError:
                print("Please enter a valid number.")
                continue

            print(f"\nCurrent description: {log.entries[index].description}")
            log.entries[index].description = input("Enter new description: ").strip()
            log._save_to_file()
            # Deliberately does NOT update the hash — that's the trap
            print(f"\n[!] Entry #{index} description changed.")
            print("[!] Hash NOT updated — run option 3 to see tamper detection.")

        elif choice == "6":
            print("Exiting. Log saved.")
            break

        else:
            print("Invalid choice, try again.")


if __name__ == "__main__":
    run_demo()
    