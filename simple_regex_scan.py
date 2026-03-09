#!/usr/bin/env python3
"""
🔍 Simple Regex Security Scanner
Modern static code analysis tool using regex patterns to identify potential security vulnerabilities.

Features:
- Multi-language support with encoding auto-detection
- Beautiful terminal output with rich formatting
- Extensible pattern management
- Progress tracking for large codebases
- JSON and plain text output formats
- Smart file filtering and size limits
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed

from charset_normalizer import from_bytes
from rich.console import Console
from rich.progress import (
    Progress, 
    SpinnerColumn, 
    TextColumn, 
    BarColumn, 
    TimeElapsedColumn,
    TimeRemainingColumn
)
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import box

# Initialize console for rich output
console = Console(highlight=False, color_system="auto")


# ──────────────────────────────────────
#  Pattern Definitions
# ──────────────────────────────────────

@dataclass
class SecurityPattern:
    """Represents a security pattern with metadata."""
    name: str
    description: str
    pattern: re.Pattern
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # INJECTION, XSS, FILE_INCLUSION, etc.
    remediation: str

class PatternManager:
    """Manages all security patterns and provides filtering capabilities."""
    
    # Predefined dangerous functions
    UNSAFE_FUNCTIONS = [
        "system", "shell_exec", "exec", "passthru", "eval", "assert",
        "popen", "pcntl_exec", "proc_open", "unserialize", "file_put_contents",
        "create_function", "preg_replace", "call_user_func", "call_user_func_array"
    ]
    
    # Common superglobals
    SUPER_GLOBALS = ['GET', 'POST', 'REQUEST', 'COOKIE', 'SERVER', 'FILES', 'SESSION']
    
    @classmethod
    def get_all_patterns(cls) -> Dict[str, SecurityPattern]:
        """Returns all predefined security patterns."""
        superglobal_pattern = r'\$_(?:' + '|'.join(cls.SUPER_GLOBALS) + r')\[[^\]]+\]'
        
        return {
            "unsafe_function_call": SecurityPattern(
                name="Unsafe Function Call",
                description="Dangerous function called with variable arguments",
                pattern=re.compile(
                    r"([ \t]*(?:" + "|".join(re.escape(f) for f in cls.UNSAFE_FUNCTIONS) + 
                    r")\s*\([^;]*\$[^;]*\)[^;]*;?)",
                    re.MULTILINE | re.DOTALL | re.IGNORECASE
                ),
                severity="CRITICAL",
                category="CODE_EXECUTION",
                remediation="Avoid using dangerous functions with user input. Use whitelisting and input validation."
            ),
            
            "direct_superglobal_access": SecurityPattern(
                name="Direct Superglobal Access",
                description="Direct access to superglobal arrays without filtering",
                pattern=re.compile(
                    r"(" + superglobal_pattern + r")",
                    re.MULTILINE
                ),
                severity="MEDIUM",
                category="INPUT_HANDLING",
                remediation="Always filter and validate superglobal input. Consider using a request wrapper."
            ),
            
            "file_inclusion": SecurityPattern(
                name="Dynamic File Inclusion",
                description="File inclusion with variable path",
                pattern=re.compile(
                    r"([ \t]*(?:include|include_once|require|require_once)[\( ]+\s*[^=;\n]*\$[^;]*;?)",
                    re.MULTILINE | re.IGNORECASE
                ),
                severity="CRITICAL",
                category="FILE_INCLUSION",
                remediation="Avoid dynamic file inclusion. Use whitelists and absolute paths."
            ),
            
            "sql_injection_variable": SecurityPattern(
                name="SQL Injection (Variable)",
                description="SQL query built with variable concatenation",
                pattern=re.compile(
                    r"(SELECT\s+.*?\s+FROM\s+.*?\s+WHERE\s+.*?['\"]\s*[+.]\s*\$[^;]*;)",
                    re.MULTILINE | re.IGNORECASE | re.DOTALL
                ),
                severity="HIGH",
                category="INJECTION",
                remediation="Use prepared statements or parameterized queries. Never concatenate variables directly."
            ),
            
            "sql_injection_superglobal": SecurityPattern(
                name="SQL Injection (Superglobal)",
                description="SQL query with direct superglobal input",
                pattern=re.compile(
                    r"(SELECT\s+.*?\s+FROM\s+.*?\s+WHERE\s+.*?['\"]\s*[+.]\s*" + 
                    superglobal_pattern + r"[^;]*;)",
                    re.MULTILINE | re.IGNORECASE | re.DOTALL
                ),
                severity="CRITICAL",
                category="INJECTION",
                remediation="Never use superglobals directly in SQL. Use prepared statements."
            ),
            
            "xss_echo": SecurityPattern(
                name="Cross-Site Scripting (XSS)",
                description="Echoing unsanitized user input",
                pattern=re.compile(
                    r"(echo|print|printf|sprintf)\s*\(?[^;]*" + 
                    superglobal_pattern + r"[^;]*;?",
                    re.MULTILINE | re.IGNORECASE
                ),
                severity="HIGH",
                category="XSS",
                remediation="Always escape output using htmlspecialchars() or a templating engine."
            ),
            
            "command_injection": SecurityPattern(
                name="Command Injection",
                description="Shell command execution with user input",
                pattern=re.compile(
                    r"(?:shell_exec|exec|passthru|system|`[^`]*\$[^`]*`)",
                    re.MULTILINE | re.IGNORECASE
                ),
                severity="CRITICAL",
                category="INJECTION",
                remediation="Avoid shell commands. Use language-native alternatives or strict input validation."
            ),
            
            "insecure_deserialization": SecurityPattern(
                name="Insecure Deserialization",
                description="Unsafe deserialization of user input",
                pattern=re.compile(
                    r"(unserialize)\s*\(\s*" + superglobal_pattern,
                    re.MULTILINE | re.IGNORECASE
                ),
                severity="CRITICAL",
                category="DESERIALIZATION",
                remediation="Avoid unserializing user input. Use JSON or other safe formats."
            )
        }


# ──────────────────────────────────────
#  Data Models
# ──────────────────────────────────────

@dataclass
class Finding:
    """Represents a single security finding."""
    file: str
    pattern_name: str
    pattern_category: str
    severity: str
    snippet: str
    line_number: int
    line_content: str
    context_before: List[str]
    context_after: List[str]
    remediation: str
    
    def to_dict(self) -> Dict:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "file": self.file,
            "pattern_name": self.pattern_name,
            "pattern_category": self.pattern_category,
            "severity": self.severity,
            "snippet": self.snippet,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "context_before": self.context_before,
            "context_after": self.context_after,
            "remediation": self.remediation
        }


@dataclass
class ScanResult:
    """Represents complete scan results."""
    scan_time: str
    files_scanned: int
    files_skipped: int
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings_by_category: Dict[str, int]
    findings: List[Finding]
    
    def to_dict(self) -> Dict:
        """Convert scan result to dictionary."""
        return {
            "scan_time": self.scan_time,
            "stats": {
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "total_findings": self.total_findings,
                "findings_by_severity": self.findings_by_severity,
                "findings_by_category": self.findings_by_category
            },
            "findings": [f.to_dict() for f in self.findings]
        }


# ──────────────────────────────────────
#  File Scanner
# ──────────────────────────────────────

class FileScanner:
    """Handles file discovery and scanning operations."""
    
    def __init__(self, max_file_size: int = 100 * 1024, context_lines: int = 2):
        self.max_file_size = max_file_size
        self.context_lines = context_lines
        self.stats = {
            "scanned": 0,
            "skipped_size": 0,
            "skipped_encoding": 0,
            "errors": 0
        }
    
    def discover_files(self, paths: List[str], extensions: Set[str]) -> List[Path]:
        """Recursively discover all files with given extensions."""
        discovered: Set[Path] = set()
        
        for path_str in paths:
            path = Path(path_str).expanduser().resolve()
            
            if not path.exists():
                console.print(f"[yellow]Warning: Path does not exist:[/] {path}")
                continue
                
            if path.is_file():
                if any(str(path).lower().endswith(ext.lower()) for ext in extensions):
                    discovered.add(path)
            else:
                # Walk directory
                for ext in extensions:
                    discovered.update(path.rglob(f"*{ext}"))
        
        return sorted(discovered)
    
    def read_file_content(self, path: Path) -> Optional[str]:
        """Read file with automatic encoding detection."""
        try:
            # Try UTF-8 first
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # Fall back to charset detection
            try:
                raw = path.read_bytes()
                detected = from_bytes(raw).best()
                
                if detected and detected.encoding:
                    return raw.decode(detected.encoding)
                else:
                    self.stats["skipped_encoding"] += 1
                    return None
                    
            except Exception as e:
                self.stats["errors"] += 1
                console.print(f"[red]Error reading {path}:[/] {e}")
                return None
    
    def get_line_context(self, lines: List[str], line_num: int) -> Tuple[List[str], str, List[str]]:
        """Get context lines around a specific line number."""
        start = max(0, line_num - self.context_lines - 1)
        end = min(len(lines), line_num + self.context_lines)
        
        context_before = lines[start:line_num - 1]
        line_content = lines[line_num - 1] if 0 <= line_num - 1 < len(lines) else ""
        context_after = lines[line_num:end]
        
        return context_before, line_content, context_after
    
    def scan_file(self, path: Path, patterns: Dict[str, SecurityPattern]) -> List[Finding]:
        """Scan a single file for security patterns."""
        # Check file size
        if path.stat().st_size > self.max_file_size:
            self.stats["skipped_size"] += 1
            return []
        
        # Read content
        content = self.read_file_content(path)
        if content is None:
            return []
        
        self.stats["scanned"] += 1
        findings = []
        lines = content.splitlines()
        
        for pattern_name, security_pattern in patterns.items():
            for match in security_pattern.pattern.finditer(content):
                # Get the matched snippet
                snippet = match.group(1) if match.groups() else match.group(0)
                
                # Find line number
                start_pos = match.start(1) if match.groups() else match.start()
                line_num = content[:start_pos].count("\n") + 1
                
                # Get context
                context_before, line_content, context_after = self.get_line_context(lines, line_num)
                
                # Clean snippet
                cleaned_snippet = re.sub(r'\s+', ' ', snippet.strip())[:200]
                
                findings.append(Finding(
                    file=str(path),
                    pattern_name=security_pattern.name,
                    pattern_category=security_pattern.category,
                    severity=security_pattern.severity,
                    snippet=cleaned_snippet,
                    line_number=line_num,
                    line_content=line_content.strip(),
                    context_before=[l.strip() for l in context_before if l.strip()],
                    context_after=[l.strip() for l in context_after if l.strip()],
                    remediation=security_pattern.remediation
                ))
        
        return findings


# ──────────────────────────────────────
#  Output Formatters
# ──────────────────────────────────────

class OutputFormatter:
    """Handles formatting and displaying scan results."""
    
    @staticmethod
    def print_summary(result: ScanResult):
        """Print a summary of scan results."""
        # Severity counts with colors
        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "blue"
        }
        
        summary = Panel.fit(
            f"[bold]Scan completed at:[/] {result.scan_time}\n"
            f"[bold]Files scanned:[/] {result.files_scanned}\n"
            f"[bold]Files skipped:[/] {result.files_skipped}\n"
            f"[bold]Total findings:[/] {result.total_findings}\n\n"
            f"[bold]Findings by severity:[/]\n" +
            "\n".join([
                f"  [{severity_colors.get(sev, 'white')}]{sev}: {count}[/]"
                for sev, count in result.findings_by_severity.items()
            ]) + "\n\n" +
            f"[bold]Findings by category:[/]\n" +
            "\n".join([
                f"  [cyan]{cat}: {count}[/]"
                for cat, count in result.findings_by_category.items()
            ]),
            title="[bold green]Scan Summary[/]",
            border_style="green"
        )
        
        console.print(summary)
    
    @staticmethod
    def print_findings(findings: List[Finding], show_context: bool = True):
        """Display findings in a formatted table."""
        if not findings:
            console.print("\n[green]✓ No security issues found![/]")
            return
        
        # Sort by severity (CRITICAL first)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda x: (severity_order.get(x.severity, 99), x.file, x.line_number))
        
        # Create main table
        table = Table(
            title=f"[bold]Security Findings ({len(findings)})[/]",
            show_header=True,
            header_style="bold magenta",
            box=box.ROUNDED,
            expand=True
        )
        
        table.add_column("File", style="cyan", ratio=2, no_wrap=False)
        table.add_column("Severity", style="bold", ratio=1)
        table.add_column("Category", style="yellow", ratio=1)
        table.add_column("Line", justify="right", style="dim", ratio=1)
        table.add_column("Finding", style="white", ratio=3)
        
        for finding in findings:
            # Color severity
            severity_colors = {
                "CRITICAL": "red bold",
                "HIGH": "orange3 bold",
                "MEDIUM": "yellow",
                "LOW": "blue"
            }
            
            table.add_row(
                Path(finding.file).name,
                f"[{severity_colors.get(finding.severity, 'white')}]{finding.severity}[/]",
                finding.pattern_category.replace("_", " ").title(),
                str(finding.line_number),
                finding.snippet
            )
        
        console.print(table)
        
        # Show detailed context if requested
        if show_context and findings:
            console.print("\n[bold]Detailed Findings:[/]")
            for i, finding in enumerate(findings[:5], 1):  # Show first 5 details
                detail = Panel(
                    f"[bold red]{finding.pattern_name}[/]\n"
                    f"[yellow]File:[/] {finding.file}:{finding.line_number}\n"
                    f"[yellow]Severity:[/] {finding.severity}\n"
                    f"[yellow]Category:[/] {finding.pattern_category}\n\n"
                    f"[bold]Code Context:[/]\n"
                    f"{'...' if finding.context_before else ''}\n" +
                    "\n".join([f"  {line}" for line in finding.context_before]) +
                    f"\n  [bold red]> {finding.line_content}[/]\n" +
                    "\n".join([f"  {line}" for line in finding.context_after]) +
                    f"{'...' if finding.context_after else ''}\n\n"
                    f"[bold]Remediation:[/]\n{inding.remediation}",
                    title=f"Finding #{i}",
                    border_style="red" if finding.severity == "CRITICAL" else "yellow",
                    width=100
                )
                console.print(detail)
                
                if i >= 5 and len(findings) > 5:
                    console.print(f"[dim]... and {len(findings) - 5} more findings (use JSON output for full details)[/]")
                    break
    
    @staticmethod
    def save_json(result: ScanResult, output_file: Path):
        """Save results as JSON."""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        console.print(f"[green]✓ Results saved to {output_file}[/]")
    
    @staticmethod
    def save_text(result: ScanResult, output_file: Path):
        """Save results as plain text."""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"Simple Regex Security Scanner Results\n")
            f.write(f"Scan Time: {result.scan_time}\n")
            f.write(f"Files Scanned: {result.files_scanned}\n")
            f.write(f"Files Skipped: {result.files_skipped}\n")
            f.write(f"Total Findings: {result.total_findings}\n")
            f.write("=" * 80 + "\n\n")
            
            for finding in result.findings:
                f.write(f"File: {finding.file}\n")
                f.write(f"Line: {finding.line_number}\n")
                f.write(f"Severity: {finding.severity}\n")
                f.write(f"Category: {finding.pattern_category}\n")
                f.write(f"Pattern: {finding.pattern_name}\n")
                f.write(f"Code: {finding.line_content}\n")
                f.write(f"Remediation: {finding.remediation}\n")
                f.write("-" * 60 + "\n")
        
        console.print(f"[green]✓ Results saved to {output_file}[/]")


# ──────────────────────────────────────
#  Main Application
# ──────────────────────────────────────

class SecurityScanner:
    """Main application class."""
    
    def __init__(self):
        self.scanner = FileScanner()
        self.formatter = OutputFormatter()
        self.pattern_manager = PatternManager()
    
    def parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(
            description="🔍 Simple Regex Security Scanner - Find potential security issues in your code",
            epilog="""
Examples:
  %(prog)s -i /var/www/html
  %(prog)s -i app/ lib/ -e .php .inc -o results.json
  %(prog)s -i src/ --severity CRITICAL HIGH --context 3
            """,
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        parser.add_argument(
            "-i", "--input", nargs="+", required=True,
            help="Files or directories to scan"
        )
        
        parser.add_argument(
            "-e", "--extension", nargs="+", default=[".php"],
            help="File extensions to scan (default: .php)"
        )
        
        parser.add_argument(
            "-o", "--output",
            help="Output file (supports .json or .txt extension)"
        )
        
        parser.add_argument(
            "--severity", nargs="+", 
            choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            help="Filter findings by severity level"
        )
        
        parser.add_argument(
            "--categories", nargs="+",
            help="Filter findings by category (e.g., INJECTION XSS)"
        )
        
        parser.add_argument(
            "--max-size", type=int, default=100 * 1024,
            help=f"Maximum file size in bytes to scan (default: 100KB)"
        )
        
        parser.add_argument(
            "--context", type=int, default=2,
            help="Number of context lines to show (default: 2)"
        )
        
        parser.add_argument(
            "--threads", type=int, default=4,
            help="Number of threads for parallel scanning (default: 4)"
        )
        
        parser.add_argument(
            "--no-color", action="store_true",
            help="Disable colored output"
        )
        
        parser.add_argument(
            "--quiet", action="store_true",
            help="Suppress progress output"
        )
        
        parser.add_argument(
            "--patterns", nargs="+",
            choices=list(PatternManager.get_all_patterns().keys()),
            help="Specific patterns to use (default: all)"
        )
        
        return parser.parse_args()
    
    def filter_patterns(self, args: argparse.Namespace) -> Dict[str, SecurityPattern]:
        """Filter patterns based on command line arguments."""
        all_patterns = PatternManager.get_all_patterns()
        
        if args.patterns:
            return {name: all_patterns[name] for name in args.patterns if name in all_patterns}
        
        return all_patterns
    
    def aggregate_stats(self, findings: List[Finding]) -> Tuple[Dict[str, int], Dict[str, int]]:
        """Aggregate findings by severity and category."""
        by_severity = {}
        by_category = {}
        
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_category[finding.pattern_category] = by_category.get(finding.pattern_category, 0) + 1
        
        return by_severity, by_category
    
    def run(self):
        """Main execution method."""
        args = self.parse_arguments()
        
        # Disable colors if requested
        if args.no_color:
            console.no_color = True
        
        # Configure scanner
        self.scanner.max_file_size = args.max_size
        self.scanner.context_lines = args.context
        
        # Get patterns
        patterns = self.filter_patterns(args)
        
        # Normalize extensions
        extensions = set()
        for ext in args.extension:
            ext = ext if ext.startswith('.') else f'.{ext}'
            extensions.add(ext.lower())
        
        # Display banner in quiet mode
        if not args.quiet:
            console.print(Panel.fit(
                "[bold cyan]🔍 Simple Regex Security Scanner[/]\n"
                "[dim]Find security issues in your code with regex patterns[/]",
                border_style="cyan"
            ))
        
        # Discover files
        if not args.quiet:
            console.print("[bold]Discovering files...[/]")
        
        files = self.scanner.discover_files(args.input, extensions)
        
        if not files:
            console.print("[yellow]No matching files found.[/]")
            return
        
        if not args.quiet:
            console.print(f"Found [cyan]{len(files)}[/] file{'s' if len(files) != 1 else ''} to scan.")
        
        # Scan files with progress
        all_findings = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            disable=args.quiet
        ) as progress:
            task = progress.add_task("[green]Scanning files...", total=len(files))
            
            # Parallel scanning with ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                future_to_file = {
                    executor.submit(self.scanner.scan_file, file, patterns): file 
                    for file in files
                }
                
                for future in as_completed(future_to_file):
                    try:
                        findings = future.result()
                        all_findings.extend(findings)
                    except Exception as e:
                        console.print(f"[red]Error scanning file: {e}[/]")
                    
                    progress.advance(task)
        
        # Filter by severity if specified
        if args.severity:
            all_findings = [f for f in all_findings if f.severity in args.severity]
        
        # Filter by category if specified
        if args.categories:
            categories = [c.upper() for c in args.categories]
            all_findings = [f for f in all_findings if f.pattern_category in categories]
        
        # Create scan result
        by_severity, by_category = self.aggregate_stats(all_findings)
        
        result = ScanResult(
            scan_time=datetime.now().isoformat(),
            files_scanned=self.scanner.stats["scanned"],
            files_skipped=self.scanner.stats["skipped_size"] + self.scanner.stats["skipped_encoding"],
            total_findings=len(all_findings),
            findings_by_severity=by_severity,
            findings_by_category=by_category,
            findings=all_findings
        )
        
        # Display summary
        self.formatter.print_summary(result)
        
        # Display findings
        if not args.quiet:
            self.formatter.print_findings(all_findings, show_context=(args.context > 0))
        
        # Save output if requested
        if args.output:
            output_path = Path(args.output)
            if output_path.suffix.lower() == '.json':
                self.formatter.save_json(result, output_path)
            else:
                self.formatter.save_text(result, output_path)
        
        # Return exit code based on findings
        return 1 if all_findings else 0


def main():
    """Entry point."""
    scanner = SecurityScanner()
    
    try:
        exit_code = scanner.run()
        sys.exit(exit_code if exit_code is not None else 0)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan interrupted by user[/]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red bold]Error:[/] {e}")
        if "--debug" in sys.argv:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()