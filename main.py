#!/usr/bin/env python3
"""
C Security Static Analyzer
A static code analyzer for detecting insecure C programming practices.
"""

import sys
import argparse
import os
from parser import CParser
from analyzer import SecurityAnalyzer, SecurityIssue
from typing import List

class CSecurityAnalyzer:
    """Main application class for C security analysis"""
    
    def __init__(self):
        self.parser = CParser()
        self.analyzer = SecurityAnalyzer()
    
    def analyze_file(self, filepath: str, use_parser: bool = False) -> List[SecurityIssue]:
        """Analyze a C source file for security vulnerabilities"""
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                source_code = file.read()
        except IOError as e:
            print(f"Error reading file {filepath}: {e}")
            return []
        
        # Clear previous analysis results
        self.analyzer.clear_issues()
        
        if use_parser:
            # Use full parser analysis (more accurate but may fail on complex code)
            try:
                ast = self.parser.parse(source_code)
                issues = self.analyzer.analyze_from_ast(ast, source_code.split('\n'))
            except Exception as e:
                print(f"Parser failed for {filepath}: {e}")
                print("Falling back to regex-based analysis...")
                issues = self.analyzer.analyze_from_source(source_code)
        else:
            # Use regex-based analysis (more robust)
            issues = self.analyzer.analyze_from_source(source_code)
        
        return issues
    
    def generate_report(self, issues: List[SecurityIssue], filepath: str) -> str:
        """Generate a formatted security report"""
        if not issues:
            return f"✅ No security issues found in {filepath}\n"
        
        # Get statistics
        stats = self.analyzer.get_statistics()
        
        report = []
        report.append("=" * 80)
        report.append(f"SECURITY ANALYSIS REPORT: {os.path.basename(filepath)}")
        report.append("=" * 80)
        report.append(f"Total Issues Found: {stats['total']}")
        report.append(f"Critical: {stats['critical']}, High: {stats['high']}, "
                     f"Medium: {stats['medium']}, Low: {stats['low']}")
        report.append("-" * 80)
        
        # Sort issues by severity and line number
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_issues = sorted(issues, key=lambda x: (severity_order[x.severity], x.line_number))
        
        for issue in sorted_issues:
            report.append(f"[{issue.severity.upper()}] Line {issue.line_number}")
            report.append(f"  Issue: {issue.message}")
            report.append(f"  Recommendation: {issue.suggestion}")
            if issue.function_name:
                report.append(f"  Function: {issue.function_name}")
            report.append("")
        
        report.append("=" * 80)
        return "\n".join(report)
    
    def analyze_directory(self, directory: str, recursive: bool = False) -> List[str]:
        """Analyze all C files in a directory"""
        c_files = []
        
        if recursive:
            for root, dirs, files in os.walk(directory):
                c_files.extend([os.path.join(root, f) for f in files 
                               if f.endswith(('.c', '.h'))])
        else:
            c_files = [os.path.join(directory, f) for f in os.listdir(directory) 
                      if f.endswith(('.c', '.h')) and os.path.isfile(os.path.join(directory, f))]
        
        return c_files

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='C Security Static Analyzer - Detect insecure C programming practices',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f vulnerable.c                    # Analyze single file
  %(prog)s -d ./src                          # Analyze directory
  %(prog)s -d ./src -r                       # Analyze directory recursively
  %(prog)s -f test.c -o report.txt           # Save report to file
  %(prog)s -f test.c --parser                # Use full parser (experimental)
        """
    )
    
    parser.add_argument('-f', '--file', type=str, help='C source file to analyze')
    parser.add_argument('-d', '--directory', type=str, help='Directory containing C files')
    parser.add_argument('-r', '--recursive', action='store_true', 
                       help='Analyze directory recursively')
    parser.add_argument('-o', '--output', type=str, help='Output file for report')
    parser.add_argument('--parser', action='store_true', 
                       help='Use full parser analysis (experimental, may fail on complex code)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'],
                       help='Filter issues by minimum severity level')
    
    args = parser.parse_args()
    
    if not args.file and not args.directory:
        parser.print_help()
        sys.exit(1)
    
    analyzer = CSecurityAnalyzer()
    all_reports = []
    total_issues = 0
    
    # Determine files to analyze
    files_to_analyze = []
    if args.file:
        if not os.path.isfile(args.file):
            print(f"Error: File '{args.file}' not found")
            sys.exit(1)
        files_to_analyze.append(args.file)
    elif args.directory:
        if not os.path.isdir(args.directory):
            print(f"Error: Directory '{args.directory}' not found")
            sys.exit(1)
        files_to_analyze = analyzer.analyze_directory(args.directory, args.recursive)
        if not files_to_analyze:
            print(f"No C files found in directory '{args.directory}'")
            sys.exit(1)
    
    # Analyze files
    for filepath in files_to_analyze:
        if args.verbose:
            print(f"Analyzing {filepath}...")
        
        issues = analyzer.analyze_file(filepath, args.parser)
        
        # Filter by severity if specified
        if args.severity:
            severity_levels = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            min_level = severity_levels[args.severity]
            issues = [issue for issue in issues 
                     if severity_levels[issue.severity] <= min_level]
        
        total_issues += len(issues)
        report = analyzer.generate_report(issues, filepath)
        all_reports.append(report)
    
    # Generate final output
    final_report = "\n\n".join(all_reports)
    
    if len(files_to_analyze) > 1:
        summary = f"\n{'='*80}\nSUMMARY: Analyzed {len(files_to_analyze)} files, found {total_issues} total issues\n{'='*80}"
        final_report += summary
    
    # Output results
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(final_report)
            print(f"Report saved to {args.output}")
        except IOError as e:
            print(f"Error writing to output file: {e}")
            sys.exit(1)
    else:
        print(final_report)
    
    # Exit with appropriate code
    sys.exit(1 if total_issues > 0 else 0)

if __name__ == "__main__":
    main()
