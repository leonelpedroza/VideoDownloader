#!/usr/bin/env python3
"""
Video Archiver - Personal Content Backup Tool
A tool for archiving and backing up video content from various platforms
for legitimate purposes such as personal archives and content preservation.

IMPORTANT: This tool is for educational and legitimate purposes only.
Users must comply with all platform terms of service and copyright laws.
Only download content you have permission to access.
"""

import os
import sys
import json
import threading
from datetime import datetime
from urllib.parse import urlparse
import yt_dlp

from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                               QHBoxLayout, QPushButton, QLineEdit, QTextEdit, 
                               QLabel, QProgressBar, QComboBox, QFileDialog,
                               QTableWidget, QTableWidgetItem, QHeaderView,
                               QMessageBox, QGroupBox, QCheckBox, QSpinBox,
                               QTabWidget)
from PySide6.QtCore import Qt, QThread, Signal, QUrl
from PySide6.QtGui import QDesktopServices


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
            ydl_opts = {
                'outtmpl': os.path.join(self.output_dir, '%(title)s_%(id)s.%(ext)s'),
                'progress_hooks': [self.progress_hook],
                'quiet': True,
                'no_warnings': True,
            }
            ydl_opts.update(self.options)
            
            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(self.url, download=True)
                title = info.get('title', 'Unknown')
                self.finished.emit(True, f"Successfully downloaded: {title}")
        except Exception as e:
            self.finished.emit(False, f"Error: {str(e)}")
    
    def stop(self):
        self._is_running = False


class VideoArchiverGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.download_thread = None
        self.download_history = []
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Video Archiver - Personal Content Backup Tool")
        self.setGeometry(100, 100, 900, 700)
        
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Legal disclaimer
        disclaimer_group = QGroupBox("⚠️ Important Legal Notice")
        disclaimer_layout = QVBoxLayout()
        disclaimer_text = QLabel(
            "This tool is for educational and legitimate purposes only:\n"
            "• Only download content you own or have explicit permission to access\n"
            "• Respect all platform terms of service and copyright laws\n"
            "• Use for personal archival, backup, or educational purposes only\n"
            "• The developers are not responsible for misuse of this tool"
        )
        disclaimer_text.setWordWrap(True)
        disclaimer_text.setStyleSheet("color: #d32f2f; font-weight: bold;")
        disclaimer_layout.addWidget(disclaimer_text)
        disclaimer_group.setLayout(disclaimer_layout)
        main_layout.addWidget(disclaimer_group)
        
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
        
        # About tab
        about_tab = QWidget()
        self.tab_widget.addTab(about_tab, "About")
        self.setup_about_tab(about_tab)
        
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
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
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
            }
            QLineEdit:focus, QComboBox:focus {
                border: 2px solid #2196F3;
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
            }
            QProgressBar {
                border: 1px solid #ddd;
                border-radius: 4px;
                text-align: center;
                background-color: #f0f0f0;
                color: #333333;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
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
            }
            QTabBar::tab:selected {
                background-color: white;
                font-weight: bold;
            }
        """)
        
    def setup_download_tab(self, parent):
        layout = QVBoxLayout(parent)
        
        # URL input section
        url_group = QGroupBox("Video URL")
        url_layout = QVBoxLayout()
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter video URL (YouTube, Vimeo, etc.)")
        url_layout.addWidget(self.url_input)
        
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
            "720p",
            "480p",
            "Audio Only"
        ])
        quality_layout.addWidget(self.quality_combo)
        quality_layout.addStretch()
        options_layout.addLayout(quality_layout)
        
        # Additional options
        self.subtitle_check = QCheckBox("Download subtitles if available")
        self.metadata_check = QCheckBox("Save video information")
        options_layout.addWidget(self.subtitle_check)
        options_layout.addWidget(self.metadata_check)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Output directory
        output_group = QGroupBox("Output Directory")
        output_layout = QHBoxLayout()
        
        self.output_dir = QLineEdit()
        self.output_dir.setText(os.path.join(os.path.expanduser("~"), "Downloads", "VideoArchiver"))
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
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(100)
        layout.addWidget(self.log_output)
        
        layout.addStretch()
        
    def setup_history_tab(self, parent):
        layout = QVBoxLayout(parent)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels([
            "Date/Time", "Platform", "Title", "Status"
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
        
    def setup_about_tab(self, parent):
        layout = QVBoxLayout(parent)
        
        about_text = QLabel(
            "<h2>Video Archiver</h2>"
            "<p>Version 1.0 - Educational Tool</p>"
            "<h3>Purpose</h3>"
            "<p>This tool is designed for legitimate content archival and backup purposes:</p>"
            "<ul>"
            "<li>Backing up your own content</li>"
            "<li>Archiving content you have permission to download</li>"
            "<li>Educational and research purposes</li>"
            "<li>Personal use within fair use guidelines</li>"
            "</ul>"
            "<h3>Legal Reminder</h3>"
            "<p><b>Users are fully responsible for:</b></p>"
            "<ul>"
            "<li>Complying with all applicable copyright laws</li>"
            "<li>Respecting platform terms of service</li>"
            "<li>Obtaining necessary permissions</li>"
            "<li>Using this tool ethically and legally</li>"
            "</ul>"
            "<p><i>The developers of this tool do not condone or support "
            "copyright infringement or any illegal use.</i></p>"
        )
        about_text.setWordWrap(True)
        about_text.setOpenExternalLinks(True)
        
        layout.addWidget(about_text)
        layout.addStretch()
        
    def detect_platform(self, url):
        domain = urlparse(url).netloc.lower()
        
        # Only detect mainstream platforms
        if any(yt in domain for yt in ['youtube.com', 'youtu.be']):
            platform = 'YouTube'
            color = '#FF0000'
        elif 'vimeo.com' in domain:
            platform = 'Vimeo'
            color = '#1ab7ea'
        elif 'dailymotion.com' in domain:
            platform = 'Dailymotion'
            color = '#0066DC'
        elif 'twitter.com' in domain or 'x.com' in domain:
            platform = 'Twitter/X'
            color = '#1DA1F2'
        else:
            platform = 'Supported Platform'
            color = '#666666'
            
        self.platform_label.setText(f"Platform: {platform}")
        self.platform_label.setStyleSheet(f"color: {color}; font-weight: bold;")
        
    def browse_output_dir(self):
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Output Directory", self.output_dir.text()
        )
        if dir_path:
            self.output_dir.setText(dir_path)
            
    def get_format_string(self):
        quality = self.quality_combo.currentText()
        
        if quality == "Best Quality":
            return 'best[ext=mp4]/best'
        elif quality == "Audio Only":
            return 'bestaudio/best'
        else:
            height = quality.replace('p', '')
            return f'best[height<={height}]'
            
    def start_download(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Warning", "Please enter a video URL")
            return
            
        # Show terms reminder
        reply = QMessageBox.question(
            self, 
            "Terms of Use Reminder",
            "By proceeding, you confirm that:\n\n"
            "• You have permission to download this content\n"
            "• You will comply with all applicable laws\n"
            "• You accept full responsibility for your actions\n\n"
            "Do you wish to continue?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply != QMessageBox.Yes:
            return
            
        # Disable download button during download
        self.download_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.log_output.clear()
        
        # Create output directory if it doesn't exist
        output_dir = self.output_dir.text()
        os.makedirs(output_dir, exist_ok=True)
        
        # Prepare download options
        options = {
            'format': self.get_format_string(),
        }
        
        if self.subtitle_check.isChecked():
            options['writesubtitles'] = True
            options['writeautomaticsub'] = True
            
        if self.metadata_check.isChecked():
            options['writeinfojson'] = True
            
        # Start download thread
        self.download_thread = DownloadThread(url, options, output_dir)
        self.download_thread.progress.connect(self.update_progress)
        self.download_thread.status.connect(self.update_status)
        self.download_thread.finished.connect(self.download_finished)
        self.download_thread.start()
        
        self.log_output.append(f"Starting download: {url}")
        
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
        
        if success:
            QMessageBox.information(self, "Success", message)
            self.status_label.setText("Download completed!")
        else:
            QMessageBox.warning(self, "Error", message)
            self.status_label.setText("Download failed!")
            
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
        platform = self.detect_platform(url)
        self.history_table.setItem(row_count, 1, QTableWidgetItem("Video"))
        
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
        
    def clear_history(self):
        reply = QMessageBox.question(
            self, "Clear History", 
            "Are you sure you want to clear the download history?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            self.history_table.setRowCount(0)
            
    def open_downloads_folder(self):
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.output_dir.text()))


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Check dependencies
    try:
        import yt_dlp
    except ImportError:
        QMessageBox.critical(
            None,
            "Missing Dependency",
            "yt-dlp is required but not installed.\n\n"
            "Please install it using:\n"
            "pip install yt-dlp"
        )
        sys.exit(1)
    
    window = VideoArchiverGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()