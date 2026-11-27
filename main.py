
import hashlib
import json
import time
from pathlib import Path
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# =====================================
# PROJECT PATHS
# =====================================

BASE_DIR = Path(__file__).resolve().parent

TEST_FOLDER = BASE_DIR / "test_folder"
BASELINE_FILE = BASE_DIR / "baseline.json"
LOG_FILE = BASE_DIR / "security.log"


# =====================================
# SECURITY ALERTS
# =====================================

def security_alert(event, filename, old_hash=None, new_hash=None):
    """Display a detailed security alert."""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "!" * 60)
    print("\a", end="")

    print(f"[SECURITY ALERT] {event}")
    print(f"[TIME] {timestamp}")
    print(f"[FILE] {filename}")

    if old_hash:
        print(f"[OLD SHA-256] {old_hash}")

    if new_hash:
        print(f"[NEW SHA-256] {new_hash}")

    print("!" * 60 + "\n")


# =====================================
# SECURITY LOGGING
# =====================================

def log_event(event, filename, old_hash=None, new_hash=None):
    """Save security events and SHA-256 evidence."""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    old_value = old_hash or "N/A"
    new_value = new_hash or "N/A"

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as log_file:

            log_file.write(
                f"{timestamp} | {event} | {filename} | "
                f"OLD_SHA256={old_value} | "
                f"NEW_SHA256={new_value}\n"
            )

    except OSError as error:
        print(f"[ERROR] Cannot write log: {error}")


# =====================================
# SHA-256 HASHING
# =====================================

def hash_file(path):
    """Calculate SHA-256 using file chunks."""

    sha256 = hashlib.sha256()

    try:
        with open(path, "rb") as file:

            while chunk := file.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    except OSError:
        return None


# =====================================
# FILE SCANNING
# =====================================

def scan_folder():
    """Calculate hashes for files in the monitored folder."""

    hashes = {}

    if not TEST_FOLDER.is_dir():
        print("[ERROR] Test folder does not exist.")
        return None

    for path in sorted(TEST_FOLDER.iterdir()):

        if path.is_file():

            file_hash = hash_file(path)

            if file_hash is not None:
                hashes[path.name] = file_hash

    return hashes


# =====================================
# BASELINE MANAGEMENT
# =====================================

def save_baseline(hashes):

    try:
        with open(BASELINE_FILE, "w", encoding="utf-8") as file:

            json.dump(hashes, file, indent=4)

        print("[SUCCESS] Original baseline saved.")

    except OSError as error:
        print(f"[ERROR] Cannot save baseline: {error}")


def load_baseline():

    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as file:

            data = json.load(file)

        if not isinstance(data, dict):
            raise ValueError("Invalid baseline format.")

        return data

    except (OSError, json.JSONDecodeError, ValueError) as error:

        print(f"[ERROR] Cannot load baseline: {error}")
        return None


# =====================================
# INITIAL INTEGRITY CHECK
# =====================================

def check_initial_changes(baseline):
    """Compare current files with the original baseline."""

    current_files = scan_folder()

    if current_files is None:
        return

    print("\n[INFO] Checking existing files...\n")

    for filename, old_hash in baseline.items():

        if filename not in current_files:

            security_alert(
                "DELETED",
                filename,
                old_hash=old_hash
            )

            log_event(
                "DELETED",
                filename,
                old_hash=old_hash
            )

        elif current_files[filename] != old_hash:

            new_hash = current_files[filename]

            security_alert(
                "MODIFIED",
                filename,
                old_hash=old_hash,
                new_hash=new_hash
            )

            log_event(
                "MODIFIED",
                filename,
                old_hash=old_hash,
                new_hash=new_hash
            )

    for filename, new_hash in current_files.items():

        if filename not in baseline:

            security_alert(
                "NEW",
                filename,
                new_hash=new_hash
            )

            log_event(
                "NEW",
                filename,
                new_hash=new_hash
            )


# =====================================
# REAL-TIME FILE MONITOR
# =====================================

class FileWatchHandler(FileSystemEventHandler):

    def __init__(self, baseline):

        self.baseline = baseline
        self.current_hashes = scan_folder() or {}
        self.last_reported = {}

    def check_file(self, path):
        """Detect new or modified files."""

        path = Path(path)
        name = path.name

        # Allow file operations to finish.
        time.sleep(0.5)

        new_hash = hash_file(path)

        if new_hash is None:
            return

        old_hash = self.current_hashes.get(name)

        if old_hash is None:
            event = "NEW"

        elif new_hash != old_hash:
            event = "MODIFIED"

        else:
            return

        # Avoid duplicate alerts.
        if self.last_reported.get(name) == new_hash:
            return

        security_alert(
            event,
            name,
            old_hash=old_hash,
            new_hash=new_hash
        )

        log_event(
            event,
            name,
            old_hash=old_hash,
            new_hash=new_hash
        )

        self.current_hashes[name] = new_hash
        self.last_reported[name] = new_hash

    def record_deletion(self, filename):
        """Record deletion using the last known SHA-256."""

        old_hash = self.current_hashes.pop(
            filename,
            self.baseline.get(filename)
        )

        if old_hash is None:

            print(
                f"[WARNING] Deleted file hash unavailable: {filename}"
            )

            return

        security_alert(
            "DELETED",
            filename,
            old_hash=old_hash
        )

        log_event(
            "DELETED",
            filename,
            old_hash=old_hash
        )

        self.last_reported.pop(filename, None)

    def on_created(self, event):

        if event.is_directory:
            return

        self.check_file(event.src_path)

    def on_modified(self, event):

        if event.is_directory:
            return

        self.check_file(event.src_path)

    def on_moved(self, event):
        """Detect files moved into or out of the monitored folder."""

        if event.is_directory:
            return

        source = Path(event.src_path)
        destination = Path(event.dest_path)

        monitored_folder = TEST_FOLDER.resolve()

        source_inside = source.parent.resolve() == monitored_folder
        destination_inside = destination.parent.resolve() == monitored_folder

        # File moved outside the monitored folder.
        # On macOS, moving a file to Trash can trigger this event.
        if source_inside and not destination_inside:

            self.record_deletion(source.name)
            return

        # File moved into the monitored folder.
        if destination_inside and not source_inside:

            self.check_file(destination)
            return

        # File renamed inside the monitored folder.
        if source_inside and destination_inside:

            if source.name != destination.name:
                self.record_deletion(source.name)

            self.check_file(destination)

    def on_deleted(self, event):

        if event.is_directory:
            return

        filename = Path(event.src_path).name

        self.record_deletion(filename)


# =====================================
# START MONITORING
# =====================================

def start_monitoring(baseline):

    event_handler = FileWatchHandler(baseline)

    observer = Observer()

    observer.schedule(
        event_handler,
        str(TEST_FOLDER),
        recursive=False
    )

    observer.start()

    print("\n==========================================")
    print("       FILEWATCH - REAL-TIME MONITOR")
    print("==========================================")

    print("[INFO] Monitoring:", TEST_FOLDER)
    print("[INFO] SHA-256 evidence logging enabled.")
    print("[INFO] File deletion and move detection enabled.")
    print("[INFO] Watching for file changes...")
    print("[INFO] Press CTRL+C to stop.\n")

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        observer.stop()

        print("\n[INFO] Monitoring stopped.")

    observer.join()


# =====================================
# MAIN FUNCTION
# =====================================

def main():

    print("\n==========================================")
    print("       FILEWATCH - INTEGRITY MONITOR")
    print("==========================================")

    current_hashes = scan_folder()

    if current_hashes is None:
        return

    if not BASELINE_FILE.exists():

        save_baseline(current_hashes)

        baseline = current_hashes

        print("[INFO] First scan completed.")

    else:

        baseline = load_baseline()

        if baseline is None:
            return

    check_initial_changes(baseline)

    start_monitoring(baseline)


if __name__ == "__main__":
    main()
