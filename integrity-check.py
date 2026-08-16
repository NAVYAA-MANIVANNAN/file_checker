#!/usr/bin/env python3
"""
File Integrity Checker – SHA-256 Log Tampering Detection Tool
Provides:
  - init <path>
  - check <path>
  - update <path>
  - help / --help
"""

import sys
import os
import hashlib
import json
import datetime

# Configure stdout to use UTF-8 if available to prevent UnicodeEncodeError in standard Windows terminals
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    if hasattr(sys.stderr, 'reconfigure'):
        sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

# Determine if the terminal can display unicode checkmark
try:
    '✓'.encode(sys.stdout.encoding or 'utf-8')
    CHECK_SYM = '✓'
except Exception:
    CHECK_SYM = 'v'  # Safe ASCII fallback

def get_db_path():
    """
    Returns the path to the baseline database file (~/.integrity_hashes.json).
    """
    return os.path.abspath(os.path.expanduser('~/.integrity_hashes.json'))

def get_canonical_path(path):
    """
    Normalizes a path to an absolute path with forward slashes for cross-platform consistency.
    """
    return os.path.abspath(path).replace('\\', '/')

def get_display_path(path):
    """
    Returns a clean display path relative to the current working directory, using forward slashes.
    """
    try:
        rel = os.path.relpath(path, os.getcwd())
        return rel.replace('\\', '/')
    except Exception:
        return path.replace('\\', '/')

def calculate_hash(filepath):
    """
    Calculates the SHA-256 hash of a file reading in chunks to prevent memory bloat.
    Handles permission or OS errors gracefully without crashing.
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as file:
            while chunk := file.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError):
        print(f"[!] Permission denied: {get_display_path(filepath)}")
        return None

def scan_directory(dir_path, db_path):
    """
    Recursively scans the directory for files, ignoring VCS, caches, and temp files.
    """
    ignored_dirs = {'.git', '__pycache__', '.venv', 'venv', 'env', '.idea', '.vscode'}
    ignored_files = {'.DS_Store', 'Thumbs.db'}
    files_to_check = []
    
    # Resolve db path to ignore it if it happens to be in the monitored dir
    abs_db_path = os.path.abspath(db_path)

    for root, dirs, files in os.walk(dir_path):
        # Modify dirs in-place to skip ignored directories recursively
        dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith('.')]
        
        for file in files:
            if file in ignored_files:
                continue
            # Ignore standard temporary patterns
            if file.endswith(('~', '.pyc', '.pyo', '.tmp')) or file.startswith(('~$', '._')):
                continue
                
            full_path = os.path.join(root, file)
            abs_path = os.path.abspath(full_path)
            
            if abs_path == abs_db_path:
                continue
                
            if os.path.isfile(abs_path):
                files_to_check.append(get_canonical_path(abs_path))
                
    return sorted(files_to_check)

def find_baseline_entry(db, canonical_path):
    """
    Looks up a canonical path in the database. Performs a case-insensitive search
    on Windows systems to handle path resolution safely.
    """
    if canonical_path in db:
        return canonical_path, db[canonical_path]
        
    if sys.platform.startswith('win'):
        lower_path = canonical_path.lower()
        for k, v in db.items():
            if k.lower() == lower_path:
                return k, v
    return None, None

def is_subpath(child_path, parent_path):
    """
    Determines if a child canonical path is nested inside a parent canonical path.
    """
    p_parts = parent_path.rstrip('/').split('/')
    c_parts = child_path.rstrip('/').split('/')
    
    if len(c_parts) < len(p_parts):
        return False
        
    if sys.platform.startswith('win'):
        return [x.lower() for x in c_parts[:len(p_parts)]] == [x.lower() for x in p_parts]
    else:
        return c_parts[:len(p_parts)] == p_parts

def get_matching_keys(db, target_canonical, is_dir):
    """
    Gets all keys in the database that match the target path (either exactly, or as children).
    """
    matching = []
    if is_dir:
        for k in db:
            if is_subpath(k, target_canonical):
                matching.append(k)
    else:
        key, _ = find_baseline_entry(db, target_canonical)
        if key:
            matching.append(key)
    return matching

def print_help():
    """
    Prints CLI help message.
    """
    print("""========================================
       FILE INTEGRITY CHECKER
       SHA-256 SECURITY MONITOR
========================================

Commands:

init    Initialize file integrity baseline
check   Check file integrity
update  Update trusted baseline
help    Show help
""")

def run_init(target_path):
    """
    Executes the 'init' command to calculate baseline hashes.
    """
    target_canonical = get_canonical_path(target_path)
    
    if not os.path.exists(target_path):
        print(f"[!] Path does not exist: {target_path}")
        sys.exit(1)
        
    db_path = get_db_path()
    
    # Ensure db directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
        except OSError:
            print(f"[!] Failed to create baseline database directory: {db_dir}")
            sys.exit(1)
            
    # Load existing database
    db = {}
    if os.path.exists(db_path):
        try:
            with open(db_path, "r", encoding="utf-8") as f:
                db = json.load(f)
            if not isinstance(db, dict):
                db = {}
        except (json.JSONDecodeError, OSError):
            print("[!] Corrupted baseline database. Overwriting with new baseline...")
            db = {}
            
    is_dir = os.path.isdir(target_path)
    
    if is_dir:
        current_files = scan_directory(target_path, db_path)
        if not current_files:
            print(f"[!] Directory is empty or contains no monitorable files: {target_path}")
            sys.exit(1)
    else:
        current_files = [target_canonical]
        
    print("[+] Initializing file integrity...")
    
    errors = 0
    new_entries = {}
    for file_path in current_files:
        if not os.path.exists(file_path):
            continue
        h = calculate_hash(file_path)
        if h is None:
            errors += 1
            continue
            
        try:
            size = os.path.getsize(file_path)
        except OSError:
            size = 0
            
        new_entries[file_path] = {
            "sha256": h,
            "size": size,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
    if not new_entries:
        print("[!] No files could be hashed (check read permissions).")
        sys.exit(1)
        
    # Remove older baseline records under this exact file or directory target
    keys_to_remove = get_matching_keys(db, target_canonical, is_dir)
    for k in keys_to_remove:
        if k in db:
            del db[k]
            
    # Update baseline and write out
    db.update(new_entries)
    
    try:
        with open(db_path, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=4)
        print("[+] SHA-256 hashes calculated.")
        print("[+] Hashes stored successfully.")
    except OSError as e:
        print(f"[!] Failed to write baseline database: {e}")
        sys.exit(1)

def run_check(target_path):
    """
    Executes the 'check' command to compare current hashes against baseline.
    """
    target_canonical = get_canonical_path(target_path)
    db_path = get_db_path()
    
    if not os.path.exists(db_path):
        print("[!] No baseline found.")
        print("Run:")
        print(f"python3 integrity-check.py init {target_path}")
        sys.exit(1)
        
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            db = json.load(f)
    except (json.JSONDecodeError, OSError):
        print(f"[!] Corrupted baseline database: {db_path}")
        print("Run init command to recreate baseline.")
        sys.exit(1)
        
    # Determine target existence
    path_exists = os.path.exists(target_path)
    is_dir = os.path.isdir(target_path) if path_exists else False
    
    # Handle deleted target file or directory check
    if not path_exists:
        # Check if the path was monitored in baseline as a directory (sub-paths)
        matching_keys = get_matching_keys(db, target_canonical, is_dir=True)
        if not matching_keys:
            # Check if it was monitored as a single file
            matching_keys = get_matching_keys(db, target_canonical, is_dir=False)
            
        if not matching_keys:
            print(f"[!] Path does not exist: {target_path}")
            sys.exit(1)
            
        # Monitored targets exist in DB but path is deleted on disk
        is_dir = len(matching_keys) > 1 or (len(matching_keys) == 1 and matching_keys[0].lower() != target_canonical.lower())
        current_files = []
    else:
        if is_dir:
            current_files = scan_directory(target_path, db_path)
        else:
            current_files = [target_canonical]
            
        matching_keys = get_matching_keys(db, target_canonical, is_dir)
        
    deleted_paths = set(matching_keys)
    
    unmodified = 0
    modified = 0
    new_files = 0
    deleted = 0
    errors = 0
    
    # 1. Compare current files with baseline
    for file_path in current_files:
        display_path = get_display_path(file_path)
        
        if not os.path.exists(file_path):
            continue
            
        key, entry = find_baseline_entry(db, file_path)
        
        if key:
            if key in deleted_paths:
                deleted_paths.remove(key)
                
            curr_hash = calculate_hash(file_path)
            if curr_hash is None:
                errors += 1
                continue
                
            if curr_hash == entry.get("sha256"):
                print(f"[{CHECK_SYM}] {display_path}")
                print(f"    Status: UNMODIFIED")
                print(f"    SHA-256: {curr_hash}")
                unmodified += 1
            else:
                print(f"[!] {display_path}")
                print(f"    Status: MODIFIED")
                print(f"    Reason: SHA-256 hash mismatch")
                modified += 1
        else:
            print(f"[+] {display_path}")
            print(f"    Status: NEW FILE")
            print(f"    Reason: File was not present during initialization")
            new_files += 1
            
    # 2. Check for files missing from filesystem
    for del_key in sorted(deleted_paths):
        display_path = get_display_path(del_key)
        print(f"[-] {display_path}")
        print(f"    Status: DELETED")
        print(f"    Reason: Previously monitored file no longer exists")
        deleted += 1
        
    # Summary Report
    print("========================================")
    print("INTEGRITY CHECK SUMMARY")
    print("========================================")
    print(f"Unmodified : {unmodified}")
    print(f"Modified   : {modified}")
    print(f"New Files  : {new_files}")
    print(f"Deleted    : {deleted}")
    print(f"Errors     : {errors}")
    print("")
    
    if modified == 0 and new_files == 0 and deleted == 0 and errors == 0:
        print("Overall Status: SECURE")
    else:
        print("Overall Status: WARNING")
    print("========================================")

def run_update(target_path, force=False):
    """
    Executes the 'update' command to refresh changed paths in the baseline database.
    Requires terminal confirmation.
    """
    target_canonical = get_canonical_path(target_path)
    db_path = get_db_path()
    
    if not os.path.exists(db_path):
        print("[!] No baseline found.")
        print("Run:")
        print(f"python3 integrity-check.py init {target_path}")
        sys.exit(1)
        
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            db = json.load(f)
    except (json.JSONDecodeError, OSError):
        print(f"[!] Corrupted baseline database: {db_path}")
        sys.exit(1)
        
    path_exists = os.path.exists(target_path)
    is_dir = os.path.isdir(target_path) if path_exists else False
    
    # Handle deleted target updates
    if not path_exists:
        matching_keys = get_matching_keys(db, target_canonical, is_dir=True)
        if not matching_keys:
            matching_keys = get_matching_keys(db, target_canonical, is_dir=False)
            
        if not matching_keys:
            print(f"[!] Path does not exist and is not monitored in baseline: {target_path}")
            sys.exit(1)
            
        is_dir = len(matching_keys) > 1 or (len(matching_keys) == 1 and matching_keys[0].lower() != target_canonical.lower())
        current_files = []
    else:
        if is_dir:
            current_files = scan_directory(target_path, db_path)
        else:
            current_files = [target_canonical]
            
        matching_keys = get_matching_keys(db, target_canonical, is_dir)
        
    modified_paths = []
    new_paths = []
    deleted_paths = []
    
    baseline_set = set(matching_keys)
    current_set = set(current_files)
    
    for file_path in current_files:
        if not os.path.exists(file_path):
            continue
        key, entry = find_baseline_entry(db, file_path)
        if key:
            curr_hash = calculate_hash(file_path)
            if curr_hash is not None and curr_hash != entry.get("sha256"):
                modified_paths.append((file_path, curr_hash))
        else:
            new_paths.append(file_path)
            
    for key in baseline_set:
        found = False
        if sys.platform.startswith('win'):
            found = any(key.lower() == c.lower() for c in current_set)
        else:
            found = key in current_set
            
        if not found:
            deleted_paths.append(key)
            
    if not modified_paths and not new_paths and not deleted_paths:
        print(f"[{CHECK_SYM}] Baseline is already up-to-date. No changes detected.")
        sys.exit(0)
        
    print("Pending Updates:")
    for path, _ in modified_paths:
        print(f"  [!] Modified: {get_display_path(path)}")
    for path in new_paths:
        print(f"  [+] New File: {get_display_path(path)}")
    for path in deleted_paths:
        print(f"  [-] Deleted: {get_display_path(path)}")
        
    if not force:
        try:
            confirm = input("Do you want to update the baseline database with these changes? (y/N): ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Update aborted by user.")
            sys.exit(1)
            
        if confirm not in ('y', 'yes'):
            print("[!] Update aborted by user.")
            sys.exit(0)
            
    print("[+] Recalculating SHA-256 hash...")
    
    # 1. Update modified files
    for path, curr_hash in modified_paths:
        key, entry = find_baseline_entry(db, path)
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        db[key] = {
            "sha256": curr_hash,
            "size": size,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
    # 2. Add new files
    for path in new_paths:
        curr_hash = calculate_hash(path)
        if curr_hash is None:
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        db[path] = {
            "sha256": curr_hash,
            "size": size,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
    # 3. Remove deleted files
    for path in deleted_paths:
        if path in db:
            del db[path]
            
    try:
        with open(db_path, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=4)
        print("[+] Baseline hash updated successfully.")
    except OSError as e:
        print(f"[!] Failed to save baseline database: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print_help()
        sys.exit(0)
        
    cmd = sys.argv[1].lower()
    
    if cmd in ('help', '--help', '-h'):
        print_help()
        sys.exit(0)
        
    if cmd not in ('init', 'check', 'update'):
        print(f"[!] Invalid command: {sys.argv[1]}")
        print_help()
        sys.exit(1)
        
    # Handle help or missing target path parameters
    if len(sys.argv) < 3:
        print(f"[!] Path argument missing for command: {cmd}")
        print(f"Usage: python3 integrity-check.py {cmd} <file-or-directory>")
        sys.exit(1)
        
    target_path = sys.argv[2]
    
    # Parse force flag (-y / --yes) for automated scripting/testing updates
    force = False
    if len(sys.argv) > 3 and sys.argv[3] in ('-y', '--yes'):
        force = True
        
    if cmd == 'init':
        run_init(target_path)
    elif cmd == 'check':
        run_check(target_path)
    elif cmd == 'update':
        run_update(target_path, force=force)

if __name__ == '__main__':
    main()
