import ply.lex as lex

class CLexer:
    """C Language Lexer for security analysis"""
    
    # Token definitions
    tokens = (
        'ID', 'NUMBER', 'STRING_LITERAL', 'CHAR_LITERAL',
        'PLUS', 'MINUS', 'TIMES', 'DIVIDE', 'MODULO',
        'ASSIGN', 'EQ', 'NE', 'LT', 'LE', 'GT', 'GE',
        'LAND', 'LOR', 'LNOT', 'AND', 'OR', 'XOR', 'NOT',
        'LSHIFT', 'RSHIFT',
        'INCREMENT', 'DECREMENT',
        'LPAREN', 'RPAREN', 'LBRACE', 'RBRACE', 'LBRACKET', 'RBRACKET',
        'COMMA', 'SEMICOLON', 'COLON', 'QUESTION', 'DOT', 'ARROW',
        'ELLIPSIS', 'POUND',
        'PLUSEQUAL', 'MINUSEQUAL', 'TIMESEQUAL', 'DIVEQUAL', 'MODEQUAL',
        'LSHIFTEQUAL', 'RSHIFTEQUAL', 'ANDEQUAL', 'OREQUAL', 'XOREQUAL',
    )
    
    # Reserved words
    reserved = {
        'auto': 'AUTO', 'break': 'BREAK', 'case': 'CASE', 'char': 'CHAR',
        'const': 'CONST', 'continue': 'CONTINUE', 'default': 'DEFAULT',
        'do': 'DO', 'double': 'DOUBLE', 'else': 'ELSE', 'enum': 'ENUM',
        'extern': 'EXTERN', 'float': 'FLOAT', 'for': 'FOR', 'goto': 'GOTO',
        'if': 'IF', 'int': 'INT', 'long': 'LONG', 'register': 'REGISTER',
        'return': 'RETURN', 'short': 'SHORT', 'signed': 'SIGNED',
        'sizeof': 'SIZEOF', 'static': 'STATIC', 'struct': 'STRUCT',
        'switch': 'SWITCH', 'typedef': 'TYPEDEF', 'union': 'UNION',
        'unsigned': 'UNSIGNED', 'void': 'VOID', 'volatile': 'VOLATILE',
        'while': 'WHILE', 'inline': 'INLINE', 'restrict': 'RESTRICT',
        '_Bool': 'BOOL', '_Complex': 'COMPLEX', '_Imaginary': 'IMAGINARY',
    }
    
    tokens = tokens + tuple(reserved.values())
    
    # Token rules
    t_PLUS = r'\+'
    t_MINUS = r'-'
    t_TIMES = r'\*'
    t_DIVIDE = r'/'
    t_MODULO = r'%'
    t_ASSIGN = r'='
    t_EQ = r'=='
    t_NE = r'!='
    t_LT = r'<'
    t_LE = r'<='
    t_GT = r'>'
    t_GE = r'>='
    t_LAND = r'&&'
    t_LOR = r'\|\|'
    t_LNOT = r'!'
    t_AND = r'&'
    t_OR = r'\|'
    t_XOR = r'\^'
    t_NOT = r'~'
    t_LSHIFT = r'<<'
    t_RSHIFT = r'>>'
    t_INCREMENT = r'\+\+'
    t_DECREMENT = r'--'
    t_LPAREN = r'\('
    t_RPAREN = r'\)'
    t_LBRACE = r'\{'
    t_RBRACE = r'\}'
    t_LBRACKET = r'\['
    t_RBRACKET = r'\]'
    t_COMMA = r','
    t_SEMICOLON = r';'
    t_COLON = r':'
    t_QUESTION = r'\?'
    t_DOT = r'\.'
    t_ARROW = r'->'
    t_ELLIPSIS = r'\.\.\.'
    t_POUND = r'\#'
    t_PLUSEQUAL = r'\+='
    t_MINUSEQUAL = r'-='
    t_TIMESEQUAL = r'\*='
    t_DIVEQUAL = r'/='
    t_MODEQUAL = r'%='
    t_LSHIFTEQUAL = r'<<='
    t_RSHIFTEQUAL = r'>>='
    t_ANDEQUAL = r'&='
    t_OREQUAL = r'\|='
    t_XOREQUAL = r'\^='
    
    def t_NUMBER(self, t):
        r'''
        ((\d*\.\d+)(E[\+-]?\d+)?[fFlL]?)|
        (\d+E[\+-]?\d+[fFlL]?)|
        (0[xX][\da-fA-F]+[lLuU]*)|
        (\d+[lLuU]*)
        '''
        return t
    
    def t_STRING_LITERAL(self, t):
        r'"([^"\\]|\\.)*"'
        return t
    
    def t_CHAR_LITERAL(self, t):
        r"'([^'\\]|\\.)*'"
        return t
    
    def t_ID(self, t):
        r'[a-zA-Z_][a-zA-Z_0-9]*'
        t.type = self.reserved.get(t.value, 'ID')
        return t
    
    def t_COMMENT_MULTILINE(self, t):
        r'/\*(.|\n)*?\*/'
        t.lexer.lineno += t.value.count('\n')
    
    def t_COMMENT_SINGLE(self, t):
        r'//.*'
        pass
    
    def t_PREPROCESSOR(self, t):
        r'\#.*'
        pass
    
    def t_newline(self, t):
        r'\n+'
        t.lexer.lineno += len(t.value)
    
    def t_whitespace(self, t):
        r'[ \t]+'
        pass
    
    def t_error(self, t):
        print(f"Illegal character '{t.value[0]}' at line {t.lineno}")
        t.lexer.skip(1)
    
    def build(self, **kwargs):
        """Build the lexer"""
        self.lexer = lex.lex(module=self, **kwargs)
        return self.lexer
    
    def tokenize(self, data):
        """Tokenize input data"""
        self.lexer.input(data)
        tokens = []
        while True:
            tok = self.lexer.token()
            if not tok:
                break
            tokens.append(tok)
        return tokens
