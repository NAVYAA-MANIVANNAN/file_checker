import unittest
from unittest.mock import patch, MagicMock
import os
import shutil
import tempfile
import json
import io
import contextlib
import importlib.util
import sys

# Dynamically import integrity-check.py (since it contains a hyphen in the filename)
spec = importlib.util.spec_from_file_location(
    "integrity_check",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../integrity-check.py"))
)
integrity_check = importlib.util.module_from_spec(spec)
sys.modules["integrity_check"] = integrity_check
spec.loader.exec_module(integrity_check)


class TestFileIntegrity(unittest.TestCase):
    
    def setUp(self):
        # Create temporary directory for isolated file operations
        self.test_dir = tempfile.mkdtemp()
        self.db_file = os.path.join(self.test_dir, ".integrity_hashes.json")
        
        # Patch get_db_path to return our test database path
        self.db_path_patcher = patch('integrity_check.get_db_path', return_value=self.db_file)
        self.mock_db_path = self.db_path_patcher.start()
        
    def tearDown(self):
        # Stop patcher and remove temp dir
        self.db_path_patcher.stop()
        try:
            shutil.rmtree(self.test_dir)
        except OSError:
            pass

    def create_test_file(self, relative_path, content):
        """Helper to create files in temp directory."""
        full_path = os.path.join(self.test_dir, relative_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        return full_path

    def test_1_hash_generation(self):
        """1. Test SHA-256 hash generation on files."""
        filepath = self.create_test_file("test.txt", "hello world")
        expected_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        
        calculated = integrity_check.calculate_hash(filepath)
        self.assertEqual(calculated, expected_hash)

    def test_2_baseline_creation(self):
        """8. Test baseline creation (init command)."""
        self.create_test_file("logs/app.log", "log content 1")
        self.create_test_file("logs/auth.log", "log content 2")
        
        stdout_capture = io.StringIO()
        with contextlib.redirect_stdout(stdout_capture):
            try:
                integrity_check.run_init(self.test_dir)
            except SystemExit:
                pass
                
        output = stdout_capture.getvalue()
        self.assertIn("Initializing file integrity", output)
        self.assertIn("hashes stored successfully", output.lower())
        
        # Assert database file exists and contains correct paths
        self.assertTrue(os.path.exists(self.db_file))
        with open(self.db_file, "r") as f:
            db_data = json.load(f)
            
        canonical_app = integrity_check.get_canonical_path(os.path.join(self.test_dir, "logs/app.log"))
        canonical_auth = integrity_check.get_canonical_path(os.path.join(self.test_dir, "logs/auth.log"))
        
        self.assertIn(canonical_app, db_data)
        self.assertIn(canonical_auth, db_data)
        self.assertEqual(db_data[canonical_app]["sha256"], integrity_check.calculate_hash(canonical_app))

    def test_3_file_unchanged(self):
        """2. Test checked files unmodified."""
        self.create_test_file("logs/app.log", "log content 1")
        
        # Run init
        try:
            integrity_check.run_init(self.test_dir)
        except SystemExit:
            pass
            
        # Run check
        stdout_capture = io.StringIO()
        with contextlib.redirect_stdout(stdout_capture):
            try:
                integrity_check.run_check(self.test_dir)
            except SystemExit:
                pass
                
        output = stdout_capture.getvalue()
        self.assertIn("[✓]", output)
        self.assertIn("logs/app.log", output.replace('\\', '/'))
        self.assertIn("Status: UNMODIFIED", output)
        self.assertIn("Overall Status: SECURE", output)

    def test_4_file_modified(self):
        """3. Test checked files modified (hash mismatch)."""
        app_path = self.create_test_file("logs/app.log", "log content 1")
        
        # Run init
        try:
            integrity_check.run_init(self.test_dir)
        except SystemExit:
            pass
            
        # Modify file
        with open(app_path, "w", encoding="utf-8") as f:
            f.write("tampered content")
            
        # Run check
        stdout_capture = io.StringIO()
        with contextlib.redirect_stdout(stdout_capture):
            try:
                integrity_check.run_check(self.test_dir)
            except SystemExit:
                pass
                
        output = stdout_capture.getvalue()
        self.assertIn("[!]", output)
        self.assertIn("logs/app.log", output.replace('\\', '/'))
        self.assertIn("Status: MODIFIED", output)
        self.assertIn("Reason: SHA-256 hash mismatch", output)
        self.assertIn("Overall Status: WARNING", output)

    def test_5_new_file(self):
        """4. Test checked new file detection."""
        self.create_test_file("logs/app.log", "log content 1")
        
        # Run init
        try:
            integrity_check.run_init(self.test_dir)
        except SystemExit:
            pass
            
        # Add new file
        self.create_test_file("logs/new.log", "new file content")
        
        # Run check
        stdout_capture = io.StringIO()
        with contextlib.redirect_stdout(stdout_capture):
            try:
                integrity_check.run_check(self.test_dir)
            except SystemExit:
                pass
                
        output = stdout_capture.getvalue()
        self.assertIn("[+]", output)
        self.assertIn("logs/new.log", output.replace('\\', '/'))
        self.assertIn("Status: NEW FILE", output)
        self.assertIn("Overall Status: WARNING", output)

    def test_6_deleted_file(self):
        """5. Test checked deleted file detection."""
        auth_path = self.create_test_file("logs/auth.log", "log content 2")
        
        # Run init
        try:
            integrity_check.run_init(self.test_dir)
        except SystemExit:
            pass
            
        # Delete file
        os.remove(auth_path)
        
        # Run check
        stdout_capture = io.StringIO()
        with contextlib.redirect_stdout(stdout_capture):
            try:
                integrity_check.run_check(self.test_dir)
            except SystemExit:
                pass
                
        output = stdout_capture.getvalue()
        self.assertIn("[-]", output)
        self.assertIn("logs/auth.log", output.replace('\\', '/'))
        self.assertIn("Status: DELETED", output)
        self.assertIn("Overall Status: WARNING", output)

    def test_7_invalid_path(self):
        """6. Test invalid path handling."""
        non_existent = os.path.join(self.test_dir, "missing_folder")
        
        # Expect system exit on invalid path
        stdout_capture = io.StringIO()
        with contextlib.redirect_stdout(stdout_capture):
            with self.assertRaises(SystemExit) as cm:
                integrity_check.run_init(non_existent)
                
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("[!] Path does not exist", stdout_capture.getvalue())

    def test_8_empty_directory(self):
        """7. Test empty directory handling."""
        empty_dir = os.path.join(self.test_dir, "empty_folder")
        os.makedirs(empty_dir, exist_ok=True)
        
        stdout_capture = io.StringIO()
        with contextlib.redirect_stdout(stdout_capture):
            with self.assertRaises(SystemExit) as cm:
                integrity_check.run_init(empty_dir)
                
        self.assertEqual(cm.exception.code, 1)
        self.assertIn("Directory is empty or contains no monitorable files", stdout_capture.getvalue())

    def test_9_baseline_update(self):
        """9. Test baseline update operations."""
        app_path = self.create_test_file("logs/app.log", "log content 1")
        auth_path = self.create_test_file("logs/auth.log", "log content 2")
        
        # Run init
        try:
            integrity_check.run_init(self.test_dir)
        except SystemExit:
            pass
            
        # 1. Modify app.log
        with open(app_path, "w", encoding="utf-8") as f:
            f.write("modified log content")
            
        # 2. Add new.log
        new_path = self.create_test_file("logs/new.log", "new log content")
        
        # 3. Delete auth.log
        os.remove(auth_path)
        
        # Run update with force=True
        stdout_capture = io.StringIO()
        with contextlib.redirect_stdout(stdout_capture):
            try:
                integrity_check.run_update(self.test_dir, force=True)
            except SystemExit:
                pass
                
        output = stdout_capture.getvalue()
        self.assertIn("Pending Updates:", output)
        self.assertIn("[!] Modified:", output)
        self.assertIn("logs/app.log", output.replace('\\', '/'))
        self.assertIn("[+] New File:", output)
        self.assertIn("logs/new.log", output.replace('\\', '/'))
        self.assertIn("[-] Deleted:", output)
        self.assertIn("logs/auth.log", output.replace('\\', '/'))
        self.assertIn("Baseline hash updated successfully", output)
        
        # Verify the database has the new values and auth.log is removed
        with open(self.db_file, "r") as f:
            db_data = json.load(f)
            
        canonical_app = integrity_check.get_canonical_path(app_path)
        canonical_auth = integrity_check.get_canonical_path(auth_path)
        canonical_new = integrity_check.get_canonical_path(new_path)
        
        self.assertIn(canonical_app, db_data)
        self.assertIn(canonical_new, db_data)
        self.assertNotIn(canonical_auth, db_data)
        self.assertEqual(db_data[canonical_app]["sha256"], integrity_check.calculate_hash(app_path))
        self.assertEqual(db_data[canonical_new]["sha256"], integrity_check.calculate_hash(new_path))
        
        # Run check now and verify SECURE status
        stdout_capture2 = io.StringIO()
        with contextlib.redirect_stdout(stdout_capture2):
            try:
                integrity_check.run_check(self.test_dir)
            except SystemExit:
                pass
        
        self.assertIn("Overall Status: SECURE", stdout_capture2.getvalue())


if __name__ == '__main__':
    unittest.main()
