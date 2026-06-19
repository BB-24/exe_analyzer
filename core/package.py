import os
import json
import zipfile
import hashlib
from pubsub import pub

class PackageModule:
    def __init__(self, config):
        """
        Initializes the Package Analysis Module.
        :param config: Dictionary loaded from config.yaml
        """
        self.config = config
        self.extract_base = self.config['system'].get('extract_dir', './workspace/extracted')
        self.max_depth = self.config['system'].get('max_unpack_depth', 3)
        
        # Targets for FR-PKG-02
        self.flagged_extensions = ['.exe', '.dll', '.sys', '.bat', '.ps1', '.vbs', '.js', '.wsf']

    def process_file(self, filepath, analysis_id):
        """
        Main entry point for the package unpacking and inventory pipeline.
        """
        pub.sendMessage("gui.log", msg="\n[+] --- Starting Package Analysis Module ---")
        
        filename = os.path.basename(filepath)
        extract_target_dir = os.path.join(self.extract_base, f"{analysis_id}_{filename}_unpacked")
        
        # Ensure base extraction directory exists
        os.makedirs(extract_target_dir, exist_ok=True)

        pub.sendMessage("gui.log", msg=f"[*] Unpacking archive to: {extract_target_dir}")
        
        # FR-PKG-01: Recursive Extraction
        self._extract_recursive(filepath, extract_target_dir, current_depth=0)

        # FR-PKG-02 & FR-PKG-03: Inventory Enumeration and Hashing
        pub.sendMessage("gui.log", msg="[*] Generating package inventory and cryptographic hashes...")
        inventory = self._generate_inventory(extract_target_dir)

        # FR-PKG-04: Write comprehensive file inventory log
        log_path = os.path.join(self.extract_base, f"{analysis_id}_inventory_log.json")
        with open(log_path, 'w') as log_file:
            json.dump(inventory, log_file, indent=4)
            
        pub.sendMessage("gui.log", msg=f"[*] Inventory log saved to: {log_path}")

        # Broadcast summary to the UI
        flagged_count = sum(1 for item in inventory if item['Is_Flagged'])
        
        summary_data = {
            "Total Files Extracted": len(inventory),
            "Flagged Payloads Found": flagged_count,
            "Max Depth Reached": max([item['Depth'] for item in inventory]) if inventory else 0,
            "Inventory Log File": os.path.basename(log_path)
        }
        
        pub.sendMessage("gui.update_table", module="Package Unpacker", data=summary_data)
        
        return extract_target_dir, inventory

    def _extract_recursive(self, archive_path, target_dir, current_depth):
        """
        Recursively extracts ZIP files up to the configured max depth (FR-PKG-01).
        """
        if current_depth > self.max_depth:
            pub.sendMessage("gui.log", msg=f"[!] Max unpack depth ({self.max_depth}) reached. Stopping recursion for {archive_path}")
            return

        try:
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                # Basic protection against absolute path ZipSlip vulnerabilities
                for member in zip_ref.namelist():
                    if member.startswith('/') or '..' in member:
                        pub.sendMessage("gui.log", msg=f"[!] Skipping suspicious path in ZIP: {member}")
                        continue
                    zip_ref.extract(member, target_dir)
                    
            # After extraction, look for nested zips in the newly extracted files
            for root, _, files in os.walk(target_dir):
                for file in files:
                    if file.lower().endswith('.zip'):
                        nested_zip_path = os.path.join(root, file)
                        # Avoid re-extracting the same file infinitely if extracted in place
                        nested_extract_dir = os.path.join(root, f"{file}_extracted")
                        if not os.path.exists(nested_extract_dir):
                            os.makedirs(nested_extract_dir, exist_ok=True)
                            self._extract_recursive(nested_zip_path, nested_extract_dir, current_depth + 1)
                            
        except zipfile.BadZipFile:
            pub.sendMessage("gui.log", msg=f"[!] Failed to unpack: {os.path.basename(archive_path)} (Bad ZIP format)")
        except Exception as e:
            pub.sendMessage("gui.log", msg=f"[!] Extraction error on {os.path.basename(archive_path)}: {str(e)}")

    def _generate_inventory(self, base_dir):
        """
        Enumerates all extracted assets, checks extensions, and calculates hashes.
        (Satisfies FR-PKG-02 and FR-PKG-03)
        """
        inventory_list = []

        for root, _, files in os.walk(base_dir):
            for file in files:
                full_path = os.path.join(root, file)
                
                # Structural Lineage (Relative Path to Root)
                rel_path = os.path.relpath(full_path, base_dir)
                
                # Calculate Depth based on folder separators
                depth = rel_path.count(os.sep)

                # FR-PKG-02: Flag embedded executables, scripts, and libraries
                _, ext = os.path.splitext(file)
                ext = ext.lower()
                is_flagged = ext in self.flagged_extensions

                # FR-PKG-03: Generate individual SHA256 hashes
                sha256_hash = self._calculate_sha256(full_path)

                if is_flagged:
                    pub.sendMessage("gui.log", msg=f"  [WARNING] Suspicious embedded file found: {rel_path}")

                inventory_item = {
                    "File_Name": file,
                    "Relative_Path": rel_path,
                    "Extension": ext,
                    "Depth": depth,
                    "Is_Flagged": is_flagged,
                    "SHA256": sha256_hash,
                    "Size_Bytes": os.path.getsize(full_path)
                }
                
                inventory_list.append(inventory_item)

        return inventory_list

    def _calculate_sha256(self, filepath):
        """Helper function to memory-efficiently calculate SHA256."""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except IOError:
            return "ERROR_READING_FILE"