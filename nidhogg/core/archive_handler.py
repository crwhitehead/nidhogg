# nidhogg/core/archive_handler.py
import zipfile
import tarfile
import os
import tempfile
import shutil
import magic  # python-magic for file type detection
from pathlib import Path
from typing import List, Optional, Tuple

from nidhogg.utils.debug import debug

class ArchiveHandler:
    """
    Handles extraction of various archive types with support for password protection.
    Currently supports ZIP files with password protection.
    """
    
    DEFAULT_PASSWORD = "infected"
    
    @staticmethod
    def is_archive(file_path: str) -> bool:
        """
        Check if a file is a recognized archive format
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            Boolean indicating if the file is a recognized archive
        """
        file_path_lower = file_path.lower()
        return (
            file_path_lower.endswith('.zip') or 
            file_path_lower.endswith('.tar') or 
            file_path_lower.endswith('.tar.gz') or 
            file_path_lower.endswith('.tgz') or
            file_path_lower.endswith('.tar.bz2')
        )
    
    @staticmethod
    def is_encrypted_zipfile(zip_path: str, zip_info: zipfile.ZipInfo) -> bool:
        """
        Check if a file within a ZIP archive is encrypted
        
        Args:
            zip_path: Path to the ZIP file
            zip_info: ZipInfo object for the file to check
            
        Returns:
            Boolean indicating if the file is encrypted
        """
        # Check for the encryption flag in the ZIP file header
        # The 6th bit (0x1) in the general purpose bit flag indicates encryption
        return (zip_info.flag_bits & 0x1) > 0
    
    @staticmethod
    def extract_archive(archive_path: str, output_dir: Optional[str] = None) -> Tuple[bool, str, List[str]]:
        """
        Extract an archive file, handling password protection if needed.
        
        Args:
            archive_path: Path to the archive file
            output_dir: Directory to extract to (if None, creates a temporary directory)
            
        Returns:
            Tuple of (success, extraction_path, extracted_files)
        """
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="nidhogg_extracted_")
        else:
            os.makedirs(output_dir, exist_ok=True)
            
        extracted_files = []
        
        try:
            archive_path_lower = archive_path.lower()
            
            # Handle ZIP files (with password support)
            if archive_path_lower.endswith('.zip'):
                success, files = ArchiveHandler._extract_zip(archive_path, output_dir)
                extracted_files.extend(files)
                return success, output_dir, extracted_files
                
            # Handle TAR files (no password support)
            elif (archive_path_lower.endswith('.tar') or
                  archive_path_lower.endswith('.tar.gz') or
                  archive_path_lower.endswith('.tgz') or
                  archive_path_lower.endswith('.tar.bz2')):
                success, files = ArchiveHandler._extract_tar(archive_path, output_dir)
                extracted_files.extend(files)
                return success, output_dir, extracted_files
                
            else:
                debug(f"Unsupported archive format: {archive_path}")
                return False, output_dir, []
                
        except Exception as e:
            debug(f"Error extracting archive {archive_path}: {str(e)}")
            return False, output_dir, extracted_files
    
    @staticmethod
    def _extract_zip(zip_path: str, output_dir: str) -> Tuple[bool, List[str]]:
        """
        Extract a ZIP file, trying with password if needed
        
        Args:
            zip_path: Path to the ZIP file
            output_dir: Directory to extract to
            
        Returns:
            Tuple of (success, list_of_extracted_files)
        """
        extracted_files = []
        
        try:
            # First attempt without password
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for zip_info in zip_ref.infolist():
                    if not zip_info.is_dir():
                        extracted_path = os.path.join(output_dir, zip_info.filename)
                        extracted_dir = os.path.dirname(extracted_path)
                        if extracted_dir:
                            os.makedirs(extracted_dir, exist_ok=True)
                        
                        # Properly check if file is encrypted before attempting extraction
                        is_encrypted = ArchiveHandler.is_encrypted_zipfile(zip_path, zip_info)
                        
                        if is_encrypted:
                            debug(f"Encrypted file detected in ZIP: {zip_info.filename}, trying with default password")
                            try:
                                with zip_ref.open(zip_info, pwd=ArchiveHandler.DEFAULT_PASSWORD.encode()) as source, open(extracted_path, 'wb') as target:
                                    shutil.copyfileobj(source, target)
                                extracted_files.append(extracted_path)
                                debug(f"Successfully extracted {zip_info.filename} using default password")
                            except Exception as pwd_error:
                                debug(f"Failed to extract with password: {str(pwd_error)}")
                        else:
                            # Not encrypted, extract normally
                            try:
                                with zip_ref.open(zip_info) as source, open(extracted_path, 'wb') as target:
                                    shutil.copyfileobj(source, target)
                                extracted_files.append(extracted_path)
                            except Exception as e:
                                debug(f"Error extracting {zip_info.filename}: {str(e)}")
                
            return True, extracted_files
            
        except zipfile.BadZipFile as e:
            debug(f"Bad ZIP file: {str(e)}")
            return False, extracted_files
            
        except Exception as e:
            debug(f"Error processing ZIP file: {str(e)}")
            return False, extracted_files
    
    @staticmethod
    def _extract_tar(tar_path: str, output_dir: str) -> Tuple[bool, List[str]]:
        """
        Extract a TAR file
        
        Args:
            tar_path: Path to the TAR file
            output_dir: Directory to extract to
            
        Returns:
            Tuple of (success, list_of_extracted_files)
        """
        extracted_files = []
        
        try:
            with tarfile.open(tar_path) as tar_ref:
                # Get list of all files (excluding directories)
                members = [m for m in tar_ref.getmembers() if m.isfile()]
                
                for member in members:
                    # Extract the file
                    try:
                        tar_ref.extract(member, path=output_dir)
                        extracted_path = os.path.join(output_dir, member.name)
                        extracted_files.append(extracted_path)
                    except Exception as e:
                        debug(f"Error extracting {member.name}: {str(e)}")
                
            return True, extracted_files
            
        except tarfile.ReadError as e:
            debug(f"Invalid TAR file: {str(e)}")
            return False, extracted_files
            
        except Exception as e:
            debug(f"Error processing TAR file: {str(e)}")
            return False, extracted_files
    
    @staticmethod
    def cleanup_extraction(extraction_dir: str) -> None:
        """
        Clean up an extraction directory
        
        Args:
            extraction_dir: Path to the extraction directory
        """
        try:
            shutil.rmtree(extraction_dir)
        except Exception as e:
            debug(f"Error cleaning up extraction directory: {str(e)}")