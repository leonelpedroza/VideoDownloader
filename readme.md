# Video Archiver - Personal Content Backup Tool

A Python-based GUI application for archiving and backing up video content from various platforms for legitimate purposes.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)

## ⚠️ Legal Disclaimer

**This tool is for educational and legitimate purposes only.**

Users must:
- Only download content they own or have explicit permission to access
- Comply with all platform terms of service
- Respect copyright laws and intellectual property rights
- Use this tool responsibly and ethically

The developers are not responsible for any misuse of this tool. By using this software, you agree to take full responsibility for your actions.

## 🎯 Legitimate Use Cases

- **Personal Content Backup**: Archive your own uploaded videos
- **Educational Resources**: Save educational content you have access to
- **Research**: Archive content for academic research (within fair use)
- **Content Migration**: Transfer your content between platforms
- **Offline Access**: Save content you're authorized to view offline

## 🚀 Features

- Clean, user-friendly GUI built with PySide6
- Support for multiple video platforms
- Quality selection (Best, 720p, 480p, Audio Only)
- Subtitle download support
- Metadata preservation
- Download history tracking
- Progress monitoring with speed display

## 📋 Requirements

- Python 3.8 or higher
- FFmpeg (for video processing)

## 🔧 Installation

1. **Clone the repository**:
```bash
git clone https://github.com/yourusername/video-archiver.git
cd video-archiver
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Install FFmpeg**:
- **Windows**: Download from [ffmpeg.org](https://ffmpeg.org/download.html) and add to PATH
- **macOS**: `brew install ffmpeg`
- **Linux**: `sudo apt install ffmpeg` (Debian/Ubuntu)

## 📖 Usage

1. **Run the application**:
```bash
python video_archiver.py
```

2. **Basic workflow**:
   - Enter the URL of the video you have permission to download
   - Select quality preferences
   - Choose output directory
   - Click "Download Video"
   - Confirm you have the right to download the content

## 🛠️ Technical Details

- **GUI Framework**: PySide6 (Qt for Python)
- **Download Engine**: yt-dlp
- **Video Processing**: FFmpeg
- **Supported Platforms**: Windows, macOS, Linux

## 📁 Project Structure

```
video-archiver/
├── video_archiver.py      # Main application
├── requirements.txt       # Python dependencies
├── README.md             # This file
└── LICENSE              # MIT License
```

## 🤝 Contributing

Contributions are welcome! However, please ensure that any contributions:
- Promote legitimate and legal use only
- Include appropriate disclaimers
- Do not facilitate copyright infringement
- Follow the existing code style

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Ethical Usage

This tool is provided for educational purposes and legitimate content archival. Users are expected to:

1. **Respect Copyright**: Only download content you have the right to access
2. **Follow Platform Rules**: Adhere to the terms of service of content platforms
3. **Personal Use**: Use downloaded content only as permitted by law
4. **No Distribution**: Do not redistribute copyrighted content

## 🚨 Important Notes

- This tool does not bypass DRM or access restrictions
- It only downloads publicly accessible content
- Users are fully responsible for their use of this tool
- Check your local laws regarding content downloading

## 🐛 Known Limitations

- Some platforms may require authentication for personal content
- Download speed depends on your internet connection
- Large files may take significant time to process

## 📞 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Ensure you're using the tool for legitimate purposes
- Include relevant error messages and system information

---

**Remember**: With great tools come great responsibilities. Use this software ethically and legally.