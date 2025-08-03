#!/usr/bin/env python3
"""
Multi-Platform Video Downloader with GUI
Supports: YouTube, Instagram, Facebook, Twitter
"""

import os
import sys
import json
import threading
from datetime import datetime
from urllib.parse import urlparse
import yt_dlp
import base64

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("Warning: cryptography module not found. Password encryption disabled.")
    print("Install with: pip install cryptography")

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QPushButton, QLineEdit, QTextEdit, 
                               QLabel, QProgressBar, QComboBox, QFileDialog,
                               QTableWidget, QTableWidgetItem, QHeaderView,
                               QMessageBox, QGroupBox, QCheckBox, QSpinBox,
                               QTabWidget, QListWidget, QListWidgetItem)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QUrl
from PySide6.QtGui import QFont, QIcon, QDesktopServices, QDragEnterEvent, QDropEvent


class PasswordManager:
    """Handles secure password storage and encryption"""
    
    def __init__(self):
        self.key_file = os.path.join(os.path.expanduser("~"), ".video_downloader_key")
        self.settings_file = os.path.join(os.path.expanduser("~"), ".video_downloader_settings.json")
        if HAS_CRYPTO:
            self.cipher = self._get_or_create_cipher()
        else:
            self.cipher = None
    
    def _get_or_create_cipher(self):
        """Get existing cipher or create new one"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            # Generate a new key
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(b"video_downloader_default_key"))
            
            # Save key
            with open(self.key_file, 'wb') as f:
                f.write(key)
            
            # Set file permissions (Windows compatible)
            if sys.platform != 'win32':
                os.chmod(self.key_file, 0o600)
        
        return Fernet(key)
    
    def encrypt_password(self, password):
        """Encrypt a password"""
        if not password or not self.cipher:
            return password
        return self.cipher.encrypt(password.encode()).decode()
    
    def decrypt_password(self, encrypted_password):
        """Decrypt a password"""
        if not encrypted_password or not self.cipher:
            return encrypted_password
        try:
            return self.cipher.decrypt(encrypted_password.encode()).decode()
        except:
            return ""
    
    def save_settings(self, settings):
        """Save settings with encrypted passwords"""
        encrypted_settings = settings.copy()
        
        # Encrypt passwords if crypto is available
        if HAS_CRYPTO:
            password_fields = [
                'ig_password', 'fb_password', 'li_password'
            ]
            
            for field in password_fields:
                if field in encrypted_settings and encrypted_settings[field]:
                    encrypted_settings[field] = self.encrypt_password(encrypted_settings[field])
        
        # Save to file
        with open(self.settings_file, 'w') as f:
            json.dump(encrypted_settings, f, indent=2)
    
    def load_settings(self):
        """Load settings and decrypt passwords"""
        if not os.path.exists(self.settings_file):
            return {}
        
        try:
            with open(self.settings_file, 'r') as f:
                encrypted_settings = json.load(f)
            
            # Decrypt passwords if crypto is available
            settings = encrypted_settings.copy()
            if HAS_CRYPTO:
                password_fields = [
                    'ig_password', 'fb_password', 'li_password'
                ]
                
                for field in password_fields:
                    if field in settings and settings[field]:
                        settings[field] = self.decrypt_password(settings[field])
            
            return settings
        except:
            return {}


class DownloadThread(QThread):
    """Thread for downloading videos without blocking the UI"""
    progress = Signal(int)
    status = Signal(str)
    finished = Signal(bool, str)
    
    def __init__(self, url, options, output_dir):
        super().__init__()
        self.url = url
        self.options = options
        self.output_dir = output_dir
        self._is_running = True
    
    def progress_hook(self, d):
        if d['status'] == 'downloading':
            if 'total_bytes' in d:
                percentage = int(d['downloaded_bytes'] * 100 / d['total_bytes'])
                self.progress.emit(percentage)
            elif 'total_bytes_estimate' in d:
                percentage = int(d['downloaded_bytes'] * 100 / d['total_bytes_estimate'])
                self.progress.emit(percentage)
            
            # Update status
            speed = d.get('speed', 0)
            if speed:
                speed_mb = speed / 1024 / 1024
                eta = d.get('eta', 0)
                self.status.emit(f"Downloading... {speed_mb:.1f} MB/s - ETA: {eta}s")
        elif d['status'] == 'finished':
            self.progress.emit(100)
            self.status.emit("Processing...")
    
    def run(self):
        try:
            # Ensure output directory exists
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
            
            ydl_opts = {
                'outtmpl': {
                    'default': os.path.join(self.output_dir, '%(title).100s_%(id)s.%(ext)s')
                },
                'progress_hooks': [self.progress_hook],
                'quiet': False,
                'no_warnings': False,
                'verbose': True,
                'restrictfilenames': True,
                'windowsfilenames': True,
                'trim_file_name': 200,
                'retries': 10,  # Add retries
                'fragment_retries': 10,
                'skip_unavailable_fragments': True,
            }
            
            # Merge options carefully
            if self.options:
                ydl_opts.update(self.options)
            
            # Override outtmpl if timestamp is enabled
            if 'outtmpl' in self.options and isinstance(self.options['outtmpl'], str):
                ydl_opts['outtmpl'] = {'default': self.options['outtmpl']}
            
            # Check for cookies file
            cookies_file = os.path.join(os.path.dirname(self.output_dir), 'cookies.txt')
            if os.path.exists(cookies_file):
                ydl_opts['cookiefile'] = cookies_file
                self.status.emit("Using cookies file for authentication")
            
            self.status.emit(f"Starting download with sanitized filenames")
            
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(self.url, download=True)
                if info:
                    title = info.get('title', 'Unknown')
                    # Sanitize title for display
                    invalid_chars = '<>:"|?*\r\n\t'
                    for char in invalid_chars:
                        title = title.replace(char, '')
                    title = ' '.join(title.split())
                    if len(title) > 100:
                        title = title[:100] + '...'
                    self.finished.emit(True, f"Successfully downloaded: {title}")
                else:
                    self.finished.emit(False, "Error: Failed to extract video information")
        except Exception as e:
            error_msg = f"Error: {str(e)}\nType: {type(e).__name__}"
            
            # Add helpful error messages for common issues
            if "Cannot parse data" in str(e):
                error_msg += "\n\nFacebook parsing error. Try:\n"
                error_msg += "1. Update yt-dlp: pip install --upgrade yt-dlp\n"
                error_msg += "2. Use authentication (Settings tab)\n"
                error_msg += "3. Try a different video URL format"
            
            import traceback
            error_msg += f"\n\nTraceback:\n{traceback.format_exc()}"
            self.finished.emit(False, error_msg)
    
    def stop(self):
        self._is_running = False


class VideoDownloaderGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.download_thread = None
        self.download_history = []
        self.password_manager = PasswordManager()
        self.setup_popup_stylesheet()
        self.check_dependencies()
        self.init_ui()
        self.load_all_settings()
        
    def setup_popup_stylesheet(self):
        """Setup stylesheet for popup windows"""
        self.popup_stylesheet = """
            QMessageBox {
                background-color: #f5f5f5;
                color: #333333;
            }
            QMessageBox QLabel {
                color: #333333;
                font-size: 13px;
            }
            QMessageBox QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                min-width: 80px;
            }
            QMessageBox QPushButton:hover {
                background-color: #45a049;
            }
            QMessageBox QPushButton:pressed {
                background-color: #3d8b40;
            }
            QDialog {
                background-color: #f5f5f5;
                color: #333333;
            }
            QDialog QLabel {
                color: #333333;
            }
            QDialog QLineEdit {
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
                background-color: white;
                color: #333333;
            }
            QDialog QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QFileDialog {
                background-color: #f5f5f5;
                color: #333333;
            }
            QFileDialog QLabel {
                color: #333333;
            }
            QFileDialog QLineEdit {
                background-color: white;
                color: #333333;
                border: 1px solid #ddd;
            }
            QFileDialog QTreeView {
                background-color: white;
                color: #333333;
                border: 1px solid #ddd;
            }
            QFileDialog QListView {
                background-color: white;
                color: #333333;
                border: 1px solid #ddd;
            }
            QFileDialog QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
            }
        """
    
    def get_popup_stylesheet(self):
        """Get the popup stylesheet"""
        return self.popup_stylesheet
        
    def check_dependencies(self):
        """Check if required dependencies are installed"""
        import subprocess
        try:
            # Check for ffmpeg
            subprocess.run(['ffmpeg', '-version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            msg = QMessageBox()
            msg.setWindowTitle("FFmpeg Not Found")
            msg.setText("FFmpeg is required but not installed.")
            msg.setInformativeText(
                "Please install FFmpeg:\n"
                "1. Download from: https://www.gyan.dev/ffmpeg/builds/\n"
                "2. Extract to C:\\ffmpeg\n"
                "3. Add C:\\ffmpeg\\bin to your system PATH\n"
                "4. Restart this application\n\n"
                "Videos may fail to download without FFmpeg."
            )
            msg.setIcon(QMessageBox.Warning)
            msg.setStyleSheet(self.get_popup_stylesheet())
            msg.exec()
        
    def init_ui(self):
        self.setWindowTitle("Multi-Platform Video Downloader")
        self.setGeometry(100, 100, 900, 700)
        self.setAcceptDrops(True)
        
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Download tab
        download_tab = QWidget()
        self.tab_widget.addTab(download_tab, "Download")
        self.setup_download_tab(download_tab)
        
        # History tab
        history_tab = QWidget()
        self.tab_widget.addTab(history_tab, "History")
        self.setup_history_tab(history_tab)
        
        # Settings tab
        settings_tab = QWidget()
        self.tab_widget.addTab(settings_tab, "Settings")
        self.setup_settings_tab(settings_tab)
        
        # Apply stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                color: #333333;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #333333;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
            QLineEdit, QComboBox {
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
                background-color: white;
                color: #333333;
                selection-background-color: #4CAF50;
                selection-color: white;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 2px solid #4CAF50;
            }
            QTextEdit {
                background-color: white;
                color: #333333;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 5px;
            }
            QLabel {
                color: #333333;
            }
            QCheckBox {
                color: #333333;
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                border: 2px solid #999999;
                background-color: white;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                border: 2px solid #4CAF50;
                background-color: #4CAF50;
                border-radius: 3px;
            }
            QSpinBox {
                padding: 5px;
                border: 1px solid #ddd;
                border-radius: 4px;
                background-color: white;
                color: #333333;
            }
            QTableWidget {
                background-color: white;
                alternate-background-color: #f9f9f9;
                color: #333333;
                gridline-color: #ddd;
                border: 1px solid #ddd;
            }
            QTableWidget::item {
                padding: 5px;
                color: #333333;
            }
            QTableWidget::item:selected {
                background-color: #4CAF50;
                color: white;
            }
            QHeaderView::section {
                background-color: #e0e0e0;
                color: #333333;
                padding: 5px;
                border: 1px solid #ccc;
                font-weight: bold;
            }
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 4px;
                text-align: center;
                background-color: #f0f0f0;
                color: #333333;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 3px;
            }
            QTabWidget::pane {
                border: 1px solid #ddd;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                color: #333333;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
                color: #333333;
                font-weight: bold;
            }
            QTabBar::tab:hover {
                background-color: #f0f0f0;
            }
            QListWidget {
                background-color: white;
                color: #333333;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            QListWidget::item {
                color: #333333;
                padding: 5px;
            }
            QListWidget::item:selected {
                background-color: #4CAF50;
                color: white;
            }
        """)
        
    def setup_download_tab(self, parent):
        layout = QVBoxLayout(parent)
        
        # URL input section
        url_group = QGroupBox("Video URL")
        url_layout = QVBoxLayout()
        
        # URL input with paste button
        url_input_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter or paste video URL here...")
        self.paste_btn = QPushButton("Paste")
        self.paste_btn.setMaximumWidth(80)
        self.paste_btn.clicked.connect(self.paste_url)
        
        url_input_layout.addWidget(self.url_input)
        url_input_layout.addWidget(self.paste_btn)
        url_layout.addLayout(url_input_layout)
        
        # Platform detection label
        self.platform_label = QLabel("Platform: Not detected")
        self.url_input.textChanged.connect(self.detect_platform)
        url_layout.addWidget(self.platform_label)
        
        url_group.setLayout(url_layout)
        layout.addWidget(url_group)
        
        # Download options
        options_group = QGroupBox("Download Options")
        options_layout = QVBoxLayout()
        
        # Quality selection
        quality_layout = QHBoxLayout()
        quality_layout.addWidget(QLabel("Quality:"))
        self.quality_combo = QComboBox()
        self.quality_combo.addItems([
            "Best Quality",
            "1080p",
            "720p", 
            "480p",
            "360p",
            "240p",
            "144p",
            "Audio Only (MP3)",
            "Custom Resolution"
        ])
        quality_layout.addWidget(self.quality_combo)
        
        # Custom resolution input
        self.custom_resolution = QLineEdit()
        self.custom_resolution.setPlaceholderText("e.g., 1920x1080")
        self.custom_resolution.setMaximumWidth(120)
        self.custom_resolution.setVisible(False)
        quality_layout.addWidget(self.custom_resolution)
        
        self.quality_combo.currentTextChanged.connect(self.on_quality_changed)
        quality_layout.addStretch()
        options_layout.addLayout(quality_layout)
        
        # Additional options
        self.subtitle_check = QCheckBox("Download subtitles if available")
        self.playlist_check = QCheckBox("Download entire playlist")
        self.metadata_check = QCheckBox("Save video metadata (for evidence)")
        self.timestamp_check = QCheckBox("Add timestamp to filename")
        options_layout.addWidget(self.subtitle_check)
        options_layout.addWidget(self.playlist_check)
        options_layout.addWidget(self.metadata_check)
        options_layout.addWidget(self.timestamp_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Output directory
        output_group = QGroupBox("Output Directory")
        output_layout = QHBoxLayout()
        
        self.output_dir = QLineEdit()
        self.output_dir.setText(os.path.join(os.path.expanduser("~"), "Downloads", "Videos"))
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_output_dir)
        
        output_layout.addWidget(self.output_dir)
        output_layout.addWidget(self.browse_btn)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Download button
        self.download_btn = QPushButton("Download Video")
        self.download_btn.clicked.connect(self.start_download)
        layout.addWidget(self.download_btn)
        
        # Progress section
        progress_group = QGroupBox("Download Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.status_label = QLabel("Ready to download")
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Log output
        log_group = QGroupBox("Log Output")
        log_layout = QVBoxLayout()
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(150)
        
        log_layout.addWidget(self.log_output)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        layout.addStretch()
        
    def setup_history_tab(self, parent):
        layout = QVBoxLayout(parent)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels([
            "Date/Time", "Platform", "Title", "Status", "Location"
        ])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        
        layout.addWidget(self.history_table)
        
        # History actions
        actions_layout = QHBoxLayout()
        self.clear_history_btn = QPushButton("Clear History")
        self.clear_history_btn.clicked.connect(self.clear_history)
        self.open_folder_btn = QPushButton("Open Downloads Folder")
        self.open_folder_btn.clicked.connect(self.open_downloads_folder)
        
        actions_layout.addWidget(self.clear_history_btn)
        actions_layout.addWidget(self.open_folder_btn)
        actions_layout.addStretch()
        
        layout.addLayout(actions_layout)
        
    def setup_settings_tab(self, parent):
        layout = QVBoxLayout(parent)
        
        # Download settings
        download_group = QGroupBox("Download Settings")
        download_layout = QVBoxLayout()
        
        # Max concurrent downloads
        concurrent_layout = QHBoxLayout()
        concurrent_layout.addWidget(QLabel("Max concurrent downloads:"))
        self.concurrent_spin = QSpinBox()
        self.concurrent_spin.setRange(1, 5)
        self.concurrent_spin.setValue(1)
        concurrent_layout.addWidget(self.concurrent_spin)
        concurrent_layout.addStretch()
        download_layout.addLayout(concurrent_layout)
        
        # Auto-retry failed downloads
        self.auto_retry_check = QCheckBox("Auto-retry failed downloads")
        download_layout.addWidget(self.auto_retry_check)
        
        download_group.setLayout(download_layout)
        layout.addWidget(download_group)
        
        # Evidence collection settings
        evidence_group = QGroupBox("Evidence Collection")
        evidence_layout = QVBoxLayout()
        
        # Hash verification
        self.hash_check = QCheckBox("Generate SHA256 hash of downloaded files")
        evidence_layout.addWidget(self.hash_check)
        
        # Screenshot capture
        self.screenshot_check = QCheckBox("Capture webpage screenshot before download")
        evidence_layout.addWidget(self.screenshot_check)
        
        # Log all activity
        self.detailed_log_check = QCheckBox("Create detailed activity log")
        self.detailed_log_check.setChecked(True)
        evidence_layout.addWidget(self.detailed_log_check)
        
        evidence_group.setLayout(evidence_layout)
        layout.addWidget(evidence_group)
        
        # Authentication settings
        auth_group = QGroupBox("Authentication (Optional)")
        auth_layout = QVBoxLayout()
        
        # Save/Load buttons
        auth_buttons_layout = QHBoxLayout()
        self.save_creds_btn = QPushButton("Save Credentials")
        self.save_creds_btn.clicked.connect(self.save_credentials)
        self.load_creds_btn = QPushButton("Load Credentials")
        self.load_creds_btn.clicked.connect(self.load_credentials)
        self.clear_creds_btn = QPushButton("Clear All")
        self.clear_creds_btn.clicked.connect(self.clear_credentials)
        
        auth_buttons_layout.addWidget(self.save_creds_btn)
        auth_buttons_layout.addWidget(self.load_creds_btn)
        auth_buttons_layout.addWidget(self.clear_creds_btn)
        auth_buttons_layout.addStretch()
        auth_layout.addLayout(auth_buttons_layout)
        
        # Instagram credentials
        ig_layout = QHBoxLayout()
        ig_layout.addWidget(QLabel("Instagram Username:"))
        self.ig_username = QLineEdit()
        ig_layout.addWidget(self.ig_username)
        auth_layout.addLayout(ig_layout)
        
        ig_pass_layout = QHBoxLayout()
        ig_pass_layout.addWidget(QLabel("Instagram Password:"))
        self.ig_password = QLineEdit()
        self.ig_password.setEchoMode(QLineEdit.Password)
        self.ig_show_pass = QCheckBox("Show")
        self.ig_show_pass.toggled.connect(lambda checked: self.ig_password.setEchoMode(
            QLineEdit.Normal if checked else QLineEdit.Password))
        ig_pass_layout.addWidget(self.ig_password)
        ig_pass_layout.addWidget(self.ig_show_pass)
        auth_layout.addLayout(ig_pass_layout)
        
        # Facebook credentials
        fb_layout = QHBoxLayout()
        fb_layout.addWidget(QLabel("Facebook Email:"))
        self.fb_email = QLineEdit()
        fb_layout.addWidget(self.fb_email)
        auth_layout.addLayout(fb_layout)
        
        fb_pass_layout = QHBoxLayout()
        fb_pass_layout.addWidget(QLabel("Facebook Password:"))
        self.fb_password = QLineEdit()
        self.fb_password.setEchoMode(QLineEdit.Password)
        self.fb_show_pass = QCheckBox("Show")
        self.fb_show_pass.toggled.connect(lambda checked: self.fb_password.setEchoMode(
            QLineEdit.Normal if checked else QLineEdit.Password))
        fb_pass_layout.addWidget(self.fb_password)
        fb_pass_layout.addWidget(self.fb_show_pass)
        auth_layout.addLayout(fb_pass_layout)
        
        # LinkedIn credentials
        li_layout = QHBoxLayout()
        li_layout.addWidget(QLabel("LinkedIn Email:"))
        self.li_email = QLineEdit()
        li_layout.addWidget(self.li_email)
        auth_layout.addLayout(li_layout)
        
        li_pass_layout = QHBoxLayout()
        li_pass_layout.addWidget(QLabel("LinkedIn Password:"))
        self.li_password = QLineEdit()
        self.li_password.setEchoMode(QLineEdit.Password)
        self.li_show_pass = QCheckBox("Show")
        self.li_show_pass.toggled.connect(lambda checked: self.li_password.setEchoMode(
            QLineEdit.Normal if checked else QLineEdit.Password))
        li_pass_layout.addWidget(self.li_password)
        li_pass_layout.addWidget(self.li_show_pass)
        auth_layout.addLayout(li_pass_layout)
        
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)
        
        # About section
        about_group = QGroupBox("About")
        about_layout = QVBoxLayout()
        
        about_text = QLabel(
            "Multi-Platform Video Downloader v1.0\n"
            "Supports: YouTube, Instagram, Facebook, Twitter\n\n"
            "Note: Please respect copyright and platform terms of service."
        )
        about_text.setWordWrap(True)
        about_layout.addWidget(about_text)
        
        about_group.setLayout(about_layout)
        layout.addWidget(about_group)
        
        layout.addStretch()
        
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            
    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            url = urls[0].toString()
            self.url_input.setText(url)
            
    def paste_url(self):
        clipboard = QApplication.clipboard()
        self.url_input.setText(clipboard.text())
        
    def detect_platform(self, url):
        domain = urlparse(url).netloc.lower()
        
        if any(yt in domain for yt in ['youtube.com', 'youtu.be']):
            platform = 'YouTube'
            color = '#FF0000'
        elif any(ig in domain for ig in ['instagram.com', 'instagr.am']):
            platform = 'Instagram'
            color = '#E1306C'
        elif 'facebook.com' in domain or 'fb.watch' in domain:
            platform = 'Facebook'
            color = '#1877F2'
        elif 'twitter.com' in domain or 'x.com' in domain:
            platform = 'Twitter/X'
            color = '#1DA1F2'
        elif 'linkedin.com' in domain:
            platform = 'LinkedIn'
            color = '#0077B5'
        elif any(site in domain for site in ['redtube.com', 'youporn.com', 'pornhub.com', 'xvideos.com']):
            platform = 'Adult Content Site'
            color = '#FF6B6B'
        else:
            platform = 'Not detected'
            color = '#666666'
            
        self.platform_label.setText(f"Platform: {platform}")
        self.platform_label.setStyleSheet(f"color: {color}; font-weight: bold;")
        return platform
        
    def browse_output_dir(self):
        dialog = QFileDialog()
        dialog.setStyleSheet(self.get_popup_stylesheet())
        dir_path = dialog.getExistingDirectory(
            self, "Select Output Directory", self.output_dir.text()
        )
        if dir_path:
            self.output_dir.setText(dir_path)
            
    def save_credentials(self):
        """Save credentials and settings"""
        settings = {
            # Credentials
            'ig_username': self.ig_username.text(),
            'ig_password': self.ig_password.text(),
            'fb_email': self.fb_email.text(),
            'fb_password': self.fb_password.text(),
            'li_email': self.li_email.text(),
            'li_password': self.li_password.text(),
            
            # Download settings
            'output_dir': self.output_dir.text(),
            'quality': self.quality_combo.currentText(),
            'subtitle_check': self.subtitle_check.isChecked(),
            'playlist_check': self.playlist_check.isChecked(),
            'metadata_check': self.metadata_check.isChecked(),
            'timestamp_check': self.timestamp_check.isChecked(),
            
            # Other settings
            'concurrent_downloads': self.concurrent_spin.value(),
            'auto_retry': self.auto_retry_check.isChecked(),
            'hash_check': self.hash_check.isChecked(),
            'screenshot_check': self.screenshot_check.isChecked(),
            'detailed_log_check': self.detailed_log_check.isChecked(),
        }
        
        self.password_manager.save_settings(settings)
        
        msg = QMessageBox()
        msg.setWindowTitle("Success")
        msg.setText("Credentials and settings saved successfully!")
        msg.setIcon(QMessageBox.Information)
        msg.setStyleSheet(self.get_popup_stylesheet())
        msg.exec()
    
    def load_credentials(self):
        """Load saved credentials and settings"""
        settings = self.password_manager.load_settings()
        
        if not settings:
            msg = QMessageBox()
            msg.setWindowTitle("Info")
            msg.setText("No saved settings found.")
            msg.setIcon(QMessageBox.Information)
            msg.setStyleSheet(self.get_popup_stylesheet())
            msg.exec()
            return
        
        # Load credentials
        self.ig_username.setText(settings.get('ig_username', ''))
        self.ig_password.setText(settings.get('ig_password', ''))
        self.fb_email.setText(settings.get('fb_email', ''))
        self.fb_password.setText(settings.get('fb_password', ''))
        self.li_email.setText(settings.get('li_email', ''))
        self.li_password.setText(settings.get('li_password', ''))
        
        # Load download settings
        if 'output_dir' in settings:
            self.output_dir.setText(settings['output_dir'])
        if 'quality' in settings:
            index = self.quality_combo.findText(settings['quality'])
            if index >= 0:
                self.quality_combo.setCurrentIndex(index)
        
        # Load checkboxes
        if 'subtitle_check' in settings:
            self.subtitle_check.setChecked(settings['subtitle_check'])
        if 'playlist_check' in settings:
            self.playlist_check.setChecked(settings['playlist_check'])
        if 'metadata_check' in settings:
            self.metadata_check.setChecked(settings['metadata_check'])
        if 'timestamp_check' in settings:
            self.timestamp_check.setChecked(settings['timestamp_check'])
        
        # Load other settings
        if 'concurrent_downloads' in settings:
            self.concurrent_spin.setValue(settings['concurrent_downloads'])
        if 'auto_retry' in settings:
            self.auto_retry_check.setChecked(settings['auto_retry'])
        if 'hash_check' in settings:
            self.hash_check.setChecked(settings['hash_check'])
        if 'screenshot_check' in settings:
            self.screenshot_check.setChecked(settings['screenshot_check'])
        if 'detailed_log_check' in settings:
            self.detailed_log_check.setChecked(settings['detailed_log_check'])
        
        msg = QMessageBox()
        msg.setWindowTitle("Success")
        msg.setText("Settings loaded successfully!")
        msg.setIcon(QMessageBox.Information)
        msg.setStyleSheet(self.get_popup_stylesheet())
        msg.exec()
    
    def clear_credentials(self):
        """Clear all credentials"""
        msg = QMessageBox()
        msg.setWindowTitle("Clear Credentials")
        msg.setText("Are you sure you want to clear all saved credentials?")
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg.setIcon(QMessageBox.Question)
        msg.setStyleSheet(self.get_popup_stylesheet())
        
        if msg.exec() == QMessageBox.Yes:
            # Clear input fields
            self.ig_username.clear()
            self.ig_password.clear()
            self.fb_email.clear()
            self.fb_password.clear()
            self.li_email.clear()
            self.li_password.clear()
            
            # Remove saved file
            if os.path.exists(self.password_manager.settings_file):
                os.remove(self.password_manager.settings_file)
            
            msg = QMessageBox()
            msg.setWindowTitle("Success")
            msg.setText("All credentials cleared!")
            msg.setIcon(QMessageBox.Information)
            msg.setStyleSheet(self.get_popup_stylesheet())
            msg.exec()
    
    def load_all_settings(self):
        """Load settings on startup"""
        settings = self.password_manager.load_settings()
        if settings:
            # Only load non-credential settings on startup
            if 'output_dir' in settings:
                self.output_dir.setText(settings['output_dir'])
            if 'quality' in settings:
                index = self.quality_combo.findText(settings['quality'])
                if index >= 0:
                    self.quality_combo.setCurrentIndex(index)
            
            # Load checkboxes
            if 'subtitle_check' in settings:
                self.subtitle_check.setChecked(settings['subtitle_check'])
            if 'playlist_check' in settings:
                self.playlist_check.setChecked(settings['playlist_check'])
            if 'metadata_check' in settings:
                self.metadata_check.setChecked(settings['metadata_check'])
            if 'timestamp_check' in settings:
                self.timestamp_check.setChecked(settings['timestamp_check'])
            
            # Load other settings
            if 'concurrent_downloads' in settings:
                self.concurrent_spin.setValue(settings['concurrent_downloads'])
            if 'auto_retry' in settings:
                self.auto_retry_check.setChecked(settings['auto_retry'])
            if 'hash_check' in settings:
                self.hash_check.setChecked(settings['hash_check'])
            if 'screenshot_check' in settings:
                self.screenshot_check.setChecked(settings['screenshot_check'])
            if 'detailed_log_check' in settings:
                self.detailed_log_check.setChecked(settings['detailed_log_check'])
    
    def on_quality_changed(self, text):
        self.custom_resolution.setVisible(text == "Custom Resolution")
        
    def get_format_string(self):
        quality = self.quality_combo.currentText()
        
        # Check if ffmpeg is available
        import shutil
        has_ffmpeg = shutil.which('ffmpeg') is not None
        
        if not has_ffmpeg:
            self.log_output.append("Warning: FFmpeg not found. Download quality may be limited.")
        
        if quality == "Best Quality":
            if has_ffmpeg:
                return 'bestvideo[ext=mp4]+bestaudio[ext=m4a]/best[ext=mp4]/best'
            else:
                return 'best[ext=mp4]/best'  # Single file, no merging needed
        elif quality == "Audio Only (MP3)":
            return 'bestaudio/best'
        elif quality == "Custom Resolution":
            resolution = self.custom_resolution.text().strip()
            if 'x' in resolution:
                width, height = resolution.split('x')
                if has_ffmpeg:
                    return f'bestvideo[width<={width}][height<={height}]+bestaudio/best'
                else:
                    return f'best[width<={width}][height<={height}]'
            else:
                return 'best'
        else:
            height = quality.replace('p', '')
            if has_ffmpeg:
                return f'bestvideo[height<={height}]+bestaudio/best[height<={height}]'
            else:
                return f'best[height<={height}]'
            
    def start_download(self):
        url = self.url_input.text().strip()
        if not url:
            msg = QMessageBox()
            msg.setWindowTitle("Warning")
            msg.setText("Please enter a video URL")
            msg.setIcon(QMessageBox.Warning)
            msg.setStyleSheet(self.get_popup_stylesheet())
            msg.exec()
            return
            
        # Disable download button during download
        self.download_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.log_output.clear()
        
        # Log initial info
        self.log_output.append(f"Starting download: {url}")
        self.log_output.append(f"Platform detected: {self.platform_label.text()}")
        
        # Create output directory if it doesn't exist
        output_dir = self.output_dir.text()
        try:
            os.makedirs(output_dir, exist_ok=True)
            self.log_output.append(f"Output directory: {output_dir}")
        except Exception as e:
            self.log_output.append(f"Error creating output directory: {e}")
            self.download_btn.setEnabled(True)
            return
        
        # Prepare download options
        options = {
            'format': self.get_format_string(),
            'merge_output_format': 'mp4' if 'Audio' not in self.quality_combo.currentText() else 'mp3',
            'http_headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            },
            'extractor_args': {
                'youtube': {'player_client': ['android', 'web']},
                'facebook': {'force_mobile': True}  # Force mobile site for better compatibility
            },
            'cookiesfrombrowser': None,  # Disable cookies for now
            'restrictfilenames': True,  # Important: sanitize filenames
            'windowsfilenames': True,  # Ensure Windows compatibility
        }
        
        # Facebook-specific handling
        platform = self.detect_platform(url)
        if 'Facebook' in platform:
            # Try to use cookies if authentication is provided
            if self.fb_email.text() and self.fb_password.text():
                options['username'] = self.fb_email.text()
                options['password'] = self.fb_password.text()
                self.log_output.append("Using Facebook authentication...")
            else:
                self.log_output.append("Note: Some Facebook videos require authentication")
            
            # Add Facebook-specific options
            options['geo_bypass'] = True
            options['geo_bypass_country'] = 'US'
        
        # Add timestamp to filename if requested
        if hasattr(self, 'timestamp_check') and self.timestamp_check.isChecked():
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Use sanitized filename template
            options['outtmpl'] = os.path.join(output_dir, f'{timestamp}_%(title).100s_%(id)s.%(ext)s')
        else:
            # Default sanitized template
            options['outtmpl'] = os.path.join(output_dir, '%(title).100s_%(id)s.%(ext)s')
        
        if self.subtitle_check.isChecked():
            options['writesubtitles'] = True
            options['writeautomaticsub'] = True
            
        if hasattr(self, 'playlist_check') and self.playlist_check.isChecked():
            options['noplaylist'] = False
        else:
            options['noplaylist'] = True
            
        # Save metadata for evidence
        if self.metadata_check.isChecked():
            options['writeinfojson'] = True
            options['writethumbnail'] = True
            
        # Add authentication if provided
        platform = self.detect_platform(url)
        if 'Instagram' in platform and self.ig_username.text() and self.ig_password.text():
            options['username'] = self.ig_username.text()
            options['password'] = self.ig_password.text()
        elif 'Facebook' in platform and self.fb_email.text() and self.fb_password.text():
            options['username'] = self.fb_email.text()
            options['password'] = self.fb_password.text()
        elif 'LinkedIn' in platform and self.li_email.text() and self.li_password.text():
            options['username'] = self.li_email.text()
            options['password'] = self.li_password.text()
            
        # Log options (without passwords)
        safe_options = options.copy()
        if 'password' in safe_options:
            safe_options['password'] = '***'
        self.log_output.append(f"Download options: {safe_options}")
        
        # Start download thread
        try:
            self.download_thread = DownloadThread(url, options, output_dir)
            self.download_thread.progress.connect(self.update_progress)
            self.download_thread.status.connect(self.update_status)
            self.download_thread.finished.connect(self.download_finished)
            self.download_thread.start()
        except Exception as e:
            self.log_output.append(f"Error starting download thread: {e}")
            self.download_btn.setEnabled(True)
        
    def update_progress(self, value):
        self.progress_bar.setValue(value)
        
    def update_status(self, status):
        self.status_label.setText(status)
        
    def download_finished(self, success, message):
        self.download_btn.setEnabled(True)
        self.log_output.append(message)
        
        # Add to history
        self.add_to_history(
            self.url_input.text(),
            "Success" if success else "Failed",
            message
        )
        
        msg = QMessageBox()
        if success:
            msg.setWindowTitle("Success")
            msg.setText(message)
            msg.setIcon(QMessageBox.Information)
            self.status_label.setText("Download completed!")
        else:
            msg.setWindowTitle("Error")
            msg.setText(message)
            msg.setIcon(QMessageBox.Warning)
            self.status_label.setText("Download failed!")
        
        msg.setStyleSheet(self.get_popup_stylesheet())
        msg.exec()
            
    def add_to_history(self, url, status, details):
        # Add to history table
        row_count = self.history_table.rowCount()
        self.history_table.insertRow(row_count)
        
        # Date/Time
        self.history_table.setItem(
            row_count, 0, 
            QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        
        # Platform
        domain = urlparse(url).netloc
        self.history_table.setItem(row_count, 1, QTableWidgetItem(domain))
        
        # Title
        title = details.split(": ")[-1] if ":" in details else "Unknown"
        self.history_table.setItem(row_count, 2, QTableWidgetItem(title))
        
        # Status
        status_item = QTableWidgetItem(status)
        if status == "Success":
            status_item.setForeground(Qt.green)
        else:
            status_item.setForeground(Qt.red)
        self.history_table.setItem(row_count, 3, status_item)
        
        # Location
        self.history_table.setItem(
            row_count, 4, 
            QTableWidgetItem(self.output_dir.text())
        )
        
    def clear_history(self):
        msg = QMessageBox()
        msg.setWindowTitle("Clear History")
        msg.setText("Are you sure you want to clear the download history?")
        msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg.setIcon(QMessageBox.Question)
        msg.setStyleSheet(self.get_popup_stylesheet())
        
        reply = msg.exec()
        if reply == QMessageBox.Yes:
            self.history_table.setRowCount(0)
            
    def open_downloads_folder(self):
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.output_dir.text()))


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = VideoDownloaderGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()