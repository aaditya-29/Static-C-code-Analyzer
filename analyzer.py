import re
from typing import List, Dict, Tuple

class SecurityIssue:
    """Represents a security vulnerability found in code"""
    
    def __init__(self, issue_type: str, line_number: int, message: str, suggestion: str, 
                 severity: str = "medium", function_name: str = None):
        self.issue_type = issue_type
        self.line_number = line_number
        self.message = message
        self.suggestion = suggestion
        self.severity = severity
        self.function_name = function_name
    
    def __str__(self):
        return f"[{self.severity.upper()}] Line {self.line_number}: {self.message} | {self.suggestion}"

class SecurityAnalyzer:
    """Static security analyzer for C code"""
    
    def __init__(self):
        self.issues = []
        self.variables = {}  # Track variable declarations and buffer sizes
        
        # Define dangerous functions and their safer alternatives
        self.dangerous_functions = {
            'gets': {
                'severity': 'high',
                'message': 'Use of dangerous function gets() can cause buffer overflow',
                'suggestion': 'Use fgets() with proper buffer size instead'
            },
            'strcpy': {
                'severity': 'high', 
                'message': 'Use of strcpy() can cause buffer overflow',
                'suggestion': 'Use strncpy() or strlcpy() with proper bounds checking'
            },
            'strcat': {
                'severity': 'high',
                'message': 'Use of strcat() can cause buffer overflow', 
                'suggestion': 'Use strncat() or strlcat() with proper bounds checking'
            },
            'sprintf': {
                'severity': 'high',
                'message': 'Use of sprintf() can cause buffer overflow',
                'suggestion': 'Use snprintf() with proper buffer size'
            },
            'scanf': {
                'severity': 'medium',
                'message': 'Use of scanf() without field width can cause buffer overflow',
                'suggestion': 'Use scanf with field width specifier (e.g., %10s) or fgets()'
            },
            'system': {
                'severity': 'critical',
                'message': 'Use of system() can lead to command injection',
                'suggestion': 'Use execve() family functions with proper input validation'
            },
            'popen': {
                'severity': 'critical', 
                'message': 'Use of popen() can lead to command injection',
                'suggestion': 'Use safer alternatives with proper input validation'
            },
            'exec': {
                'severity': 'critical',
                'message': 'Use of exec*() functions can be dangerous with user input',
                'suggestion': 'Validate and sanitize all input before using exec functions'
            },
            'execl': {
                'severity': 'critical',
                'message': 'Use of execl() can be dangerous with user input',
                'suggestion': 'Validate and sanitize all input'
            },
            'execlp': {
                'severity': 'critical',
                'message': 'Use of execlp() can be dangerous with user input', 
                'suggestion': 'Validate and sanitize all input'
            },
            'execle': {
                'severity': 'critical',
                'message': 'Use of execle() can be dangerous with user input',
                'suggestion': 'Validate and sanitize all input'
            },
            'execv': {
                'severity': 'critical',
                'message': 'Use of execv() can be dangerous with user input',
                'suggestion': 'Validate and sanitize all input'
            },
            'execvp': {
                'severity': 'critical',
                'message': 'Use of execvp() can be dangerous with user input',
                'suggestion': 'Validate and sanitize all input'
            },
            'execve': {
                'severity': 'medium',
                'message': 'Use of execve() - ensure proper input validation',
                'suggestion': 'This is safer than other exec functions but still validate input'
            }
        }
    
    def analyze_from_ast(self, ast, source_lines: List[str] = None):
        """Analyze AST for security vulnerabilities"""
        if not ast:
            return self.issues
            
        self._analyze_node(ast, source_lines)
        return self.issues
    
    def analyze_from_source(self, source_code: str):
        """Analyze source code directly using regex patterns"""
        lines = source_code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('//') or line.startswith('/*'):
                continue
                
            # Check for dangerous function calls
            self._check_dangerous_functions(line, line_num)
            
            # Check for scanf with %s without width specifier
            self._check_scanf_format_string(line, line_num)
            
            # Check for buffer declarations
            self._check_buffer_declarations(line, line_num)
            
            # Check for potential format string vulnerabilities
            self._check_format_string_vulnerabilities(line, line_num)
        
        return self.issues
    
    def _analyze_node(self, node, source_lines, current_function=None):
        """Recursively analyze AST nodes"""
        if not node:
            return
            
        # Track current function context
        if node.type == 'function_definition':
            # Extract function name from declarator
            current_function = self._extract_function_name(node)
        
        # Check for function calls
        elif node.type == 'function_call':
            self._analyze_function_call(node, current_function)
        
        # Track variable declarations  
        elif node.type == 'declaration':
            self._analyze_declaration(node)
        
        # Recursively analyze children
        if hasattr(node, 'children') and node.children:
            for child in node.children:
                self._analyze_node(child, source_lines, current_function)
    
    def _extract_function_name(self, function_node):
        """Extract function name from function definition node"""
        for child in function_node.children:
            if child.type == 'declarator':
                for subchild in child.children:
                    if subchild.type == 'direct_declarator' and subchild.value:
                        return subchild.value
        return "unknown"
    
    def _analyze_function_call(self, call_node, current_function):
        """Analyze function calls for security issues"""
        if not call_node.children:
            return
            
        func_name_node = call_node.children[0]
        if func_name_node.type == 'identifier' and func_name_node.value:
            func_name = func_name_node.value
            
            # Check if it's a dangerous function
            if func_name in self.dangerous_functions:
                danger_info = self.dangerous_functions[func_name]
                issue = SecurityIssue(
                    issue_type="dangerous_function",
                    line_number=call_node.lineno or 0,
                    message=danger_info['message'],
                    suggestion=danger_info['suggestion'],
                    severity=danger_info['severity'],
                    function_name=current_function
                )
                self.issues.append(issue)
    
    def _analyze_declaration(self, decl_node):
        """Analyze variable declarations, particularly arrays"""
        # This would extract buffer size information for bounds checking
        # Simplified implementation
        pass
    
    def _check_dangerous_functions(self, line: str, line_num: int):
        """Check for dangerous function calls using regex"""
        for func_name, danger_info in self.dangerous_functions.items():
            # Create pattern to match function calls
            pattern = rf'\b{func_name}\s*\('
            if re.search(pattern, line):
                issue = SecurityIssue(
                    issue_type="dangerous_function",
                    line_number=line_num,
                    message=danger_info['message'],
                    suggestion=danger_info['suggestion'],
                    severity=danger_info['severity']
                )
                self.issues.append(issue)
    
    def _check_scanf_format_string(self, line: str, line_num: int):
        """Check for scanf with %s without width specifier"""
        scanf_pattern = r'scanf\s*\([^)]*%s[^)]*\)'
        width_pattern = r'scanf\s*\([^)]*%\d+s[^)]*\)'
        
        if re.search(scanf_pattern, line):
            # Check if it has width specifier
            if not re.search(width_pattern, line):
                issue = SecurityIssue(
                    issue_type="unsafe_scanf",
                    line_number=line_num,
                    message="scanf() with %s format specifier without width limit",
                    suggestion="Use field width specifier like %10s or use fgets() instead",
                    severity="medium"
                )
                self.issues.append(issue)
    
    def _check_buffer_declarations(self, line: str, line_num: int):
        """Track buffer declarations for size analysis"""
        # Match char array declarations: char buffer[SIZE] or char *buffer
        char_array_pattern = r'char\s+(\w+)\s*\[(\d*)\]'
        char_pointer_pattern = r'char\s*\*\s*(\w+)'
        
        match = re.search(char_array_pattern, line)
        if match:
            var_name = match.group(1)
            size = match.group(2)
            self.variables[var_name] = {
                'type': 'char_array',
                'size': int(size) if size else None,
                'line': line_num
            }
        
        match = re.search(char_pointer_pattern, line)
        if match:
            var_name = match.group(1)
            self.variables[var_name] = {
                'type': 'char_pointer',
                'size': None,
                'line': line_num
            }
    
    def _check_format_string_vulnerabilities(self, line: str, line_num: int):
        """Check for potential format string vulnerabilities"""
        # Check for printf-family functions with variable format strings
        format_functions = ['printf', 'fprintf', 'sprintf', 'snprintf', 'syslog']
        
        for func in format_functions:
            # Pattern to match function call with variable as first argument
            pattern = rf'{func}\s*\(\s*(\w+)[^)]*\)'
            match = re.search(pattern, line)
            if match:
                # Check if the first argument is a variable (not a string literal)
                first_arg = match.group(1)
                if not (first_arg.startswith('"') and first_arg.endswith('"')):
                    issue = SecurityIssue(
                        issue_type="format_string_vulnerability",
                        line_number=line_num,
                        message=f"Potential format string vulnerability in {func}()",
                        suggestion=f"Use {func} with literal format string or validate input",
                        severity="high"
                    )
                    self.issues.append(issue)
    
    def get_issues_by_severity(self, severity: str) -> List[SecurityIssue]:
        """Get issues filtered by severity level"""
        return [issue for issue in self.issues if issue.severity == severity]
    
    def get_statistics(self) -> Dict[str, int]:
        """Get statistics about found issues"""
        stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'total': 0}
        for issue in self.issues:
            stats[issue.severity] += 1
            stats['total'] += 1
        return stats
    
    def clear_issues(self):
        """Clear all found issues"""
        self.issues = []
        self.variables = {}
