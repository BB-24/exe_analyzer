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

    def process_file(self, filepath):
        """
        Main entry point for the intake module pipeline.
        """
        pub.sendMessage("gui.log", msg=f"\n[+] --- Starting Intake Module ---")
        pub.sendMessage("gui.log", msg=f"[*] Target: {filepath}")

        if not os.path.exists(filepath):
            pub.sendMessage("gui.log", msg="[!] Error: File does not exist.")
            return None

        # FR-INT-01: File Size Validation
        file_size = os.path.getsize(filepath)
        if file_size > self.max_size_bytes:
            pub.sendMessage("gui.log", msg=f"[!] Reject: File size ({file_size} bytes) exceeds {self.max_size_bytes} bytes limit.")
            return None

        # FR-INT-02: Extension Validation
        filename = os.path.basename(filepath)
        _, ext = os.path.splitext(filename)
        ext = ext.lower()
        if ext not in self.allowed_extensions:
            pub.sendMessage("gui.log", msg=f"[!] Reject: Invalid file extension '{ext}'. Allowed: {self.allowed_extensions}")
            return None

        # FR-INT-05: Generate Unique Sequential Analysis ID
        # Using a timestamp prefix guarantees sequential sorting, and UUID guarantees global uniqueness.
        timestamp_prefix = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        unique_tail = uuid.uuid4().hex[:6].upper()
        analysis_id = f"MARS-{timestamp_prefix}-{unique_tail}"

        # Prepare for FR-INT-03 (Hashing) and FR-INT-04 (Metadata)
        pub.sendMessage("gui.log", msg="[*] Computing hashes and extracting metadata...")
        
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        # Read the first 8 bytes for Magic Bytes extraction before iterating chunks
        magic_bytes = b""
        
        # FR-INT-03: Compute hashes simultaneously using a memory-efficient chunked reader
        try:
            with open(filepath, "rb") as f:
                # Grab the first 8 bytes for FR-INT-04 magic byte validation
                magic_bytes = f.read(8)
                f.seek(0) # Reset pointer back to the start for accurate hashing

                # Read in 64KB chunks to handle large files (up to 5GB) without memory exhaustion
                for chunk in iter(lambda: f.read(65536), b""):
                    for h in hashes.values():
                        h.update(chunk)
        except IOError as e:
            pub.sendMessage("gui.log", msg=f"[!] IOError during file read: {str(e)}")
            return None

        # Resolve MIME type / Magic Bytes mapping manually for security tooling
        magic_hex = magic_bytes.hex().upper()
        mime_guess = self._guess_mime_from_magic(magic_hex, ext)

        # FR-INT-04: Extract Core Metadata
        # Handle cross-platform creation time (Windows vs Linux/Mac)
        creation_time = os.path.getctime(filepath)
        formatted_ctime = datetime.datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')

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