# Simple Regex Scan 🔍

A lightweight Python-based static code analyzer that uses regular expressions to identify potentially insecure code patterns. Perfect for quick security assessments and code reviews.

<p>
<a href="#"><img src="https://img.shields.io/badge/python-3.6%2B-red" alt="Python 3.6+"></a>
<a href="#"><img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS-%23557ef6" alt="Platform: linux, macOS"></a>
<a href="https://github.com/DustinBorn/SimpleRegexScan/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
</p>

---

## 📋 Overview

Simple Regex Scan performs static analysis on your codebase by matching files against predefined and custom regex patterns. While it doesn't analyze data flow (which may result in false positives), it's an excellent tool for:

- 🔒 Identifying common security vulnerabilities
- 📝 Code review automation
- 🚨 Quick security assessments
- 🔧 Custom pattern matching

> **Note:** This tool is particularly effective for PHP code but works well with any programming language.

---

## 🚀 Installation

### Quick Install (Recommended)
```bash
# Run the installation script (requires root for symlink creation)
./install.sh
```

### Manual Installation
```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Create symbolic link (optional)
ln -sf "$(pwd)/simple_regex_scan.py" /usr/local/bin/simple_regex_scan
```

---

## 📖 Usage

### Basic Syntax
```bash
simple_regex_scan [options] -i INPUT [INPUT ...]
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-i, --input` | **Required.** Files/directories to scan |
| `-e, --extension` | File extension to scan (default: php) |
| `-c, --custom-regex` | Add custom regex patterns |
| `-o, --output` | Save results to file |
| `--no-color` | Disable colored output |

### Predefined Regex Patterns

| Flag | Pattern | Description | Example |
|------|---------|-------------|---------|
| `-u, --unsafe-func` | Unsafe function with variable | `eval($_REQUEST['cmd'])` |
| `-f, --file-inclusion` | Variable-based file inclusion | `include 'modules/'.$_REQUEST['module']` |
| `-k, --cookie-usage` | Cookie access | `$_COOKIE['ID']` |
| `-s, --sqli` | SQL injection with direct params | `"... WHERE ID = '".$_REQUEST['ID']."'"` |
| `-S, --sqli-all` | SQL injection with any variable | `"... WHERE ID = '".$id."'"` |
| `-x, --xss` | XSS with direct params | `echo 'Username: '.$_REQUEST['user']` |

> **Note:** By default, all predefined patterns are used. Specify individual flags to use only selected patterns.

---

## 💡 Examples

### Basic Scan
```bash
# Scan all PHP files in a directory using default patterns
simple_regex_scan -i /var/www/html/myapp
```

### Custom Pattern Scan
```bash
# Scan for file inclusions and custom eval patterns
simple_regex_scan -f -c "(eval.*\(.*\$.*\);)" -i ./src
```

### Advanced Usage
```bash
# Scan multiple directories, use specific patterns, and save output
simple_regex_scan -u -s -x -i ./app ./modules -o results.txt
```

### Different File Types
```bash
# Scan JavaScript files for security issues
simple_regex_scan -e js -i ./public/js
```

---

## ⚙️ How It Works

1. **File Discovery**: Recursively scans specified directories for files with matching extensions
2. **Pattern Matching**: Applies regex patterns to each line of code
3. **Result Analysis**: Highlights matches with context lines
4. **Reporting**: Displays results with file names, line numbers, and matched code

### Performance Considerations
- Files larger than 50 KiB are automatically skipped
- Results show the line containing the match plus one line of context
- Color-coded output for easy identification of matches

---

## 🎯 Use Cases

- **Security Audits**: Quick preliminary security assessments
- **CI/CD Integration**: Automate security checks in your pipeline
- **Code Review**: Identify potential issues before peer review
- **Legacy Code Analysis**: Scan old codebases for known vulnerabilities
- **Custom Pattern Detection**: Find specific code patterns across your project

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

- 🐛 Report bugs via GitHub Issues
- 💡 Suggest new features or patterns
- 🔧 Submit pull requests
- 📚 Improve documentation

**Contact**: [dustin.born@gmx.de](mailto:dustin.born@gmx.de)

---

## ⚠️ Important Notes

- This tool generates **false positives** - always verify findings manually
- Designed for **static analysis only** - doesn't execute code
- Best used as part of a **comprehensive security strategy**
- Regular updates of regex patterns recommended

---

## 📄 License

MIT License - See [LICENSE](https://github.com/DustinBorn/SimpleRegexScan/blob/master/LICENSE) for details.

---

## 🌟 Acknowledgments

Created by Dustin Born - a simple solution for regex-based code analysis that prioritizes ease of use and flexibility.
