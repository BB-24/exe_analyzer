import os
import time
import hashlib
import uuid
import datetime
from pubsub import pub

class IntakeModule:
    def __init__(self, config):
        """
        Initializes the Intake Module with system configurations.
        :param config: Dictionary loaded from config.yaml
        """
        self.config = config
        self.max_size_bytes = self.config['system'].get('max_file_size_gb', 5) * (1024 ** 3)
        self.allowed_extensions = self.config['system'].get('allowed_extensions', ['.zip', '.exe', '.dll', '.msi'])

    def process_file(self, filepath, original_filename=""):
        """
        Main entry point for the intake module pipeline.
        """
        pub.sendMessage("gui.log", msg=f"\n[+] --- Starting Intake Module ---")
        pub.sendMessage("gui.log", msg=f"[*] Target: {filepath}")

        if not os.path.exists(filepath):
            pub.sendMessage("gui.log", msg="[!] Warning: File does not exist (likely quarantined or deleted by Host AV).")

        # FR-INT-01: File Size Validation
        file_size = 0
        try:
            if os.path.exists(filepath):
                file_size = os.path.getsize(filepath)
            else:
                pub.sendMessage("gui.log", msg=f"[!] Warning: File '{filepath}' does not exist on disk (likely quarantined or blocked).")
        except Exception as size_err:
            pub.sendMessage("gui.log", msg=f"[!] Warning: Could not get file size for '{filepath}': {size_err}")

        if file_size > self.max_size_bytes:
            pub.sendMessage("gui.log", msg=f"[!] Reject: File size ({file_size} bytes) exceeds {self.max_size_bytes} bytes limit.")
            return None

        # FR-INT-02: Extension Validation
        filename = original_filename or os.path.basename(filepath)
        _, ext = os.path.splitext(filename)
        ext = ext.lower()
        if ext not in self.allowed_extensions:
            pub.sendMessage("gui.log", msg=f"[!] Reject: Invalid file extension '{ext}'. Allowed: {self.allowed_extensions}")
            return None

        # FR-INT-05: Generate Unique Sequential Analysis ID
        # Using a UUID tail guarantees global uniqueness.
        unique_tail = uuid.uuid4().hex[:6].upper()
        
        import re
        safe_fname = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
        analysis_id = f"MARS-{safe_fname}-{unique_tail}"

        # Prepare for FR-INT-03 (Hashing) and FR-INT-04 (Metadata)
        pub.sendMessage("gui.log", msg="[*] Hashing file and extracting metadata...")
        
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        # Read the first 8 bytes for Magic Bytes extraction before iterating chunks
        magic_bytes = b""
        
        # Try to parse SHA256 from path or filename if hashing fails
        fallback_sha256 = ""
        basename_no_ext, _ = os.path.splitext(os.path.basename(filepath))
        if len(basename_no_ext) == 64 and all(c in "0123456789abcdefABCDEF" for c in basename_no_ext):
            fallback_sha256 = basename_no_ext.lower()

        # FR-INT-03: Compute hashes simultaneously using a memory-efficient chunked reader
        hashing_successful = False
        try:
            with open(filepath, "rb") as f:
                # Grab the first 8 bytes for FR-INT-04 magic byte validation
                magic_bytes = f.read(8)
                f.seek(0) # Reset pointer back to the start for accurate hashing

                # Read in 64KB chunks to handle large files (up to 5GB) without memory exhaustion
                for chunk in iter(lambda: f.read(65536), b""):
                    for h in hashes.values():
                        h.update(chunk)
            hashing_successful = True
        except (IOError, OSError) as e:
            pub.sendMessage("gui.log", msg=f"[!] IOError during file read (likely AV quarantine or block): {str(e)}")
            hashing_successful = False

        # Resolve MIME type / Magic Bytes mapping manually for security tooling
        magic_hex = magic_bytes.hex().upper()
        mime_guess = self._guess_mime_from_magic(magic_hex, ext) if magic_bytes else "Unknown (AV Blocked)"

        # FR-INT-04: Extract Core Metadata
        # Handle cross-platform creation time (Windows vs Linux/Mac)
        formatted_ctime = "Unknown"
        try:
            if os.path.exists(filepath):
                creation_time = os.path.getctime(filepath)
                formatted_ctime = datetime.datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
            else:
                formatted_ctime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            formatted_ctime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if hashing_successful:
            metadata = {
                "Analysis ID": analysis_id,
                "Original File Name": filename,
                "File Size (Bytes)": file_size,
                "Extension": ext,
                "Creation Timestamp": formatted_ctime,
                "Magic Bytes (Hex)": magic_hex[:8], # Show first 4 bytes standard
                "MIME/Format Guess": mime_guess,
                "MD5": hashes['md5'].hexdigest(),
                "SHA1": hashes['sha1'].hexdigest(),
                "SHA256": hashes['sha256'].hexdigest(),
                "SHA512": hashes['sha512'].hexdigest()
            }
        else:
            # Construct a safe fallback metadata block to prevent pipeline failure
            metadata = {
                "Analysis ID": analysis_id,
                "Original File Name": filename,
                "File Size (Bytes)": file_size,
                "Extension": ext,
                "Creation Timestamp": formatted_ctime,
                "Magic Bytes (Hex)": "N/A",
                "MIME/Format Guess": "Blocked/Quarantined by Host AV",
                "MD5": "UNKNOWN (AV BLOCKED)",
                "SHA1": "UNKNOWN (AV BLOCKED)",
                "SHA256": fallback_sha256 or "UNKNOWN (AV BLOCKED)",
                "SHA512": "UNKNOWN (AV BLOCKED)"
            }

        # Broadcast results to the UI
        pub.sendMessage("gui.log", msg=f"[*] Intake Complete. ID: {analysis_id}")
        pub.sendMessage("gui.update_table", module="Intake", data=metadata)

        return metadata

    def _guess_mime_from_magic(self, magic_hex, ext):
        """
        Helper method to evaluate file signatures (magic numbers).
        Provides a basic MIME/Type verification layer.
        """
        if magic_hex.startswith("4D5A"):  # MZ header
            return "application/x-msdownload (PE Executable)"
        elif magic_hex.startswith("504B0304"):  # PK header
            return "application/zip (ZIP Archive / MSI)"
        elif magic_hex.startswith("D0CF11E0"):  # OLE header
            return "application/x-msi (MSI Installer)"
        else:
            return f"Unknown / Assumed {ext}"