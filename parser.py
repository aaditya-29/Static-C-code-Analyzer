import ply.yacc as yacc
from lexer import CLexer

class ASTNode:
    """Base class for AST nodes"""
    def __init__(self, type, children=None, value=None, lineno=None):
        self.type = type
        self.children = children or []
        self.value = value
        self.lineno = lineno
        
    def add_child(self, child):
        self.children.append(child)
    
    def __repr__(self):
        return f"ASTNode({self.type}, {self.value}, line={self.lineno})"

class CParser:
    """C Language Parser for security analysis"""
    
    tokens = CLexer.tokens
    
    def __init__(self):
        self.lexer = CLexer()
        self.lexer.build()
        self.parser = None
        self.ast = None
        
    def p_translation_unit(self, p):
        '''translation_unit : external_declaration_list'''
        p[0] = ASTNode('translation_unit', [p[1]], lineno=p.lineno(1))
        
    def p_external_declaration_list(self, p):
        '''external_declaration_list : external_declaration
                                    | external_declaration_list external_declaration'''
        if len(p) == 2:
            p[0] = ASTNode('external_declaration_list', [p[1]])
        else:
            p[1].add_child(p[2])
            p[0] = p[1]
    
    def p_external_declaration(self, p):
        '''external_declaration : function_definition
                               | declaration'''
        p[0] = p[1]
    
    def p_function_definition(self, p):
        '''function_definition : declaration_specifiers declarator declaration_list compound_statement
                              | declaration_specifiers declarator compound_statement
                              | declarator declaration_list compound_statement
                              | declarator compound_statement'''
        if len(p) == 5:
            p[0] = ASTNode('function_definition', [p[1], p[2], p[3], p[4]], lineno=p.lineno(1))
        elif len(p) == 4 and p[2].type == 'declarator':
            p[0] = ASTNode('function_definition', [p[1], p[2], p[3]], lineno=p.lineno(1))
        else:
            p[0] = ASTNode('function_definition', p[1:], lineno=p.lineno(1))
    
    def p_declaration_specifiers(self, p):
        '''declaration_specifiers : storage_class_specifier declaration_specifiers
                                 | storage_class_specifier
                                 | type_specifier declaration_specifiers
                                 | type_specifier
                                 | type_qualifier declaration_specifiers
                                 | type_qualifier'''
        if len(p) == 2:
            p[0] = ASTNode('declaration_specifiers', [p[1]], lineno=p.lineno(1))
        else:
            p[0] = ASTNode('declaration_specifiers', [p[1], p[2]], lineno=p.lineno(1))
    
    def p_storage_class_specifier(self, p):
        '''storage_class_specifier : EXTERN
                                  | STATIC
                                  | AUTO
                                  | REGISTER'''
        p[0] = ASTNode('storage_class_specifier', value=p[1], lineno=p.lineno(1))
    
    def p_type_specifier(self, p):
        '''type_specifier : VOID
                         | CHAR
                         | SHORT
                         | INT
                         | LONG
                         | FLOAT
                         | DOUBLE
                         | SIGNED
                         | UNSIGNED
                         | BOOL
                         | COMPLEX
                         | IMAGINARY
                         | struct_or_union_specifier
                         | enum_specifier
                         | typedef_name'''
        if isinstance(p[1], str):
            p[0] = ASTNode('type_specifier', value=p[1], lineno=p.lineno(1))
        else:
            p[0] = p[1]
    
    def p_type_qualifier(self, p):
        '''type_qualifier : CONST
                         | RESTRICT
                         | VOLATILE'''
        p[0] = ASTNode('type_qualifier', value=p[1], lineno=p.lineno(1))
    
    def p_declarator(self, p):
        '''declarator : pointer direct_declarator
                     | direct_declarator'''
        if len(p) == 3:
            p[0] = ASTNode('declarator', [p[1], p[2]], lineno=p.lineno(1))
        else:
            p[0] = ASTNode('declarator', [p[1]], lineno=p.lineno(1))
    
    def p_direct_declarator(self, p):
        '''direct_declarator : ID
                            | LPAREN declarator RPAREN
                            | direct_declarator LBRACKET constant_expression RBRACKET
                            | direct_declarator LBRACKET RBRACKET
                            | direct_declarator LPAREN parameter_type_list RPAREN
                            | direct_declarator LPAREN identifier_list RPAREN
                            | direct_declarator LPAREN RPAREN'''
        if len(p) == 2:
            p[0] = ASTNode('direct_declarator', value=p[1], lineno=p.lineno(1))
        elif len(p) == 4 and p[2] == '(':
            if p[1] == '(':
                p[0] = ASTNode('direct_declarator', [p[2]], lineno=p.lineno(1))
            else:
                p[0] = ASTNode('direct_declarator', [p[1]], lineno=p.lineno(1))
        elif len(p) == 5:
            p[0] = ASTNode('direct_declarator', [p[1], p[3]], lineno=p.lineno(1))
        else:
            p[0] = ASTNode('direct_declarator', [p[1]], lineno=p.lineno(1))
    
    def p_pointer(self, p):
        '''pointer : TIMES
                  | TIMES type_qualifier_list
                  | TIMES pointer
                  | TIMES type_qualifier_list pointer'''
        p[0] = ASTNode('pointer', children=p[1:], lineno=p.lineno(1))
    
    def p_compound_statement(self, p):
        '''compound_statement : LBRACE RBRACE
                             | LBRACE block_item_list RBRACE'''
        if len(p) == 3:
            p[0] = ASTNode('compound_statement', lineno=p.lineno(1))
        else:
            p[0] = ASTNode('compound_statement', [p[2]], lineno=p.lineno(1))
    
    def p_block_item_list(self, p):
        '''block_item_list : block_item
                          | block_item_list block_item'''
        if len(p) == 2:
            p[0] = ASTNode('block_item_list', [p[1]], lineno=p.lineno(1))
        else:
            p[1].add_child(p[2])
            p[0] = p[1]
    
    def p_block_item(self, p):
        '''block_item : declaration
                     | statement'''
        p[0] = p[1]
    
    def p_declaration(self, p):
        '''declaration : declaration_specifiers SEMICOLON
                      | declaration_specifiers init_declarator_list SEMICOLON'''
        if len(p) == 3:
            p[0] = ASTNode('declaration', [p[1]], lineno=p.lineno(1))
        else:
            p[0] = ASTNode('declaration', [p[1], p[2]], lineno=p.lineno(1))
    
    def p_init_declarator_list(self, p):
        '''init_declarator_list : init_declarator
                               | init_declarator_list COMMA init_declarator'''
        if len(p) == 2:
            p[0] = ASTNode('init_declarator_list', [p[1]], lineno=p.lineno(1))
        else:
            p[1].add_child(p[3])
            p[0] = p[1]
    
    def p_init_declarator(self, p):
        '''init_declarator : declarator
                          | declarator ASSIGN initializer'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('init_declarator', [p[1], p[3]], lineno=p.lineno(1))
    
    def p_statement(self, p):
        '''statement : labeled_statement
                    | compound_statement
                    | expression_statement
                    | selection_statement
                    | iteration_statement
                    | jump_statement'''
        p[0] = p[1]
    
    def p_expression_statement(self, p):
        '''expression_statement : SEMICOLON
                               | expression SEMICOLON'''
        if len(p) == 2:
            p[0] = ASTNode('expression_statement', lineno=p.lineno(1))
        else:
            p[0] = ASTNode('expression_statement', [p[1]], lineno=p.lineno(1))
    
    def p_expression(self, p):
        '''expression : assignment_expression
                     | expression COMMA assignment_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('expression', [p[1], p[3]], lineno=p.lineno(1))
    
    def p_assignment_expression(self, p):
        '''assignment_expression : conditional_expression
                                | unary_expression assignment_operator assignment_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('assignment_expression', [p[1], p[2], p[3]], lineno=p.lineno(1))
    
    def p_conditional_expression(self, p):
        '''conditional_expression : logical_or_expression
                                 | logical_or_expression QUESTION expression COLON conditional_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('conditional_expression', [p[1], p[3], p[5]], lineno=p.lineno(1))
    
    def p_logical_or_expression(self, p):
        '''logical_or_expression : logical_and_expression
                                | logical_or_expression LOR logical_and_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('logical_or_expression', [p[1], p[3]], lineno=p.lineno(1))
    
    def p_logical_and_expression(self, p):
        '''logical_and_expression : inclusive_or_expression
                                 | logical_and_expression LAND inclusive_or_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('logical_and_expression', [p[1], p[3]], lineno=p.lineno(1))
    
    def p_inclusive_or_expression(self, p):
        '''inclusive_or_expression : exclusive_or_expression
                                  | inclusive_or_expression OR exclusive_or_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('inclusive_or_expression', [p[1], p[3]], lineno=p.lineno(1))
    
    def p_exclusive_or_expression(self, p):
        '''exclusive_or_expression : and_expression
                                  | exclusive_or_expression XOR and_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('exclusive_or_expression', [p[1], p[3]], lineno=p.lineno(1))
    
    def p_and_expression(self, p):
        '''and_expression : equality_expression
                         | and_expression AND equality_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('and_expression', [p[1], p[3]], lineno=p.lineno(1))
    
    def p_equality_expression(self, p):
        '''equality_expression : relational_expression
                              | equality_expression EQ relational_expression
                              | equality_expression NE relational_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('equality_expression', [p[1], p[3]], value=p[2], lineno=p.lineno(1))
    
    def p_relational_expression(self, p):
        '''relational_expression : shift_expression
                                | relational_expression LT shift_expression
                                | relational_expression GT shift_expression
                                | relational_expression LE shift_expression
                                | relational_expression GE shift_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('relational_expression', [p[1], p[3]], value=p[2], lineno=p.lineno(1))
    
    def p_shift_expression(self, p):
        '''shift_expression : additive_expression
                           | shift_expression LSHIFT additive_expression
                           | shift_expression RSHIFT additive_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('shift_expression', [p[1], p[3]], value=p[2], lineno=p.lineno(1))
    
    def p_additive_expression(self, p):
        '''additive_expression : multiplicative_expression
                              | additive_expression PLUS multiplicative_expression
                              | additive_expression MINUS multiplicative_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('additive_expression', [p[1], p[3]], value=p[2], lineno=p.lineno(1))
    
    def p_multiplicative_expression(self, p):
        '''multiplicative_expression : cast_expression
                                    | multiplicative_expression TIMES cast_expression
                                    | multiplicative_expression DIVIDE cast_expression
                                    | multiplicative_expression MODULO cast_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('multiplicative_expression', [p[1], p[3]], value=p[2], lineno=p.lineno(1))
    
    def p_cast_expression(self, p):
        '''cast_expression : unary_expression
                          | LPAREN type_name RPAREN cast_expression'''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ASTNode('cast_expression', [p[2], p[4]], lineno=p.lineno(1))
    
    def p_unary_expression(self, p):
        '''unary_expression : postfix_expression
                           | INCREMENT unary_expression
                           | DECREMENT unary_expression
                           | unary_operator cast_expression
                           | SIZEOF unary_expression
                           | SIZEOF LPAREN type_name RPAREN'''
        if len(p) == 2:
            p[0] = p[1]
        elif len(p) == 3:
            p[0] = ASTNode('unary_expression', [p[2]], value=p[1], lineno=p.lineno(1))
        elif len(p) == 5:
            p[0] = ASTNode('unary_expression', [p[3]], value='sizeof', lineno=p.lineno(1))
    
    def p_postfix_expression(self, p):
        '''postfix_expression : primary_expression
                             | postfix_expression LBRACKET expression RBRACKET
                             | postfix_expression LPAREN RPAREN
                             | postfix_expression LPAREN argument_expression_list RPAREN
                             | postfix_expression DOT ID
                             | postfix_expression ARROW ID
                             | postfix_expression INCREMENT
                             | postfix_expression DECREMENT'''
        if len(p) == 2:
            p[0] = p[1]
        elif len(p) == 3:
            p[0] = ASTNode('postfix_expression', [p[1]], value=p[2], lineno=p.lineno(1))
        elif len(p) == 4 and p[2] == '(':
            p[0] = ASTNode('function_call', [p[1]], lineno=p.lineno(1))
        elif len(p) == 4:
            p[0] = ASTNode('postfix_expression', [p[1]], value=p[3], lineno=p.lineno(1))
        elif len(p) == 5 and p[2] == '[':
            p[0] = ASTNode('array_access', [p[1], p[3]], lineno=p.lineno(1))
        elif len(p) == 5 and p[2] == '(':
            p[0] = ASTNode('function_call', [p[1], p[3]], lineno=p.lineno(1))
    
    def p_primary_expression(self, p):
        '''primary_expression : ID
                             | constant
                             | string
                             | LPAREN expression RPAREN'''
        if len(p) == 2:
            if isinstance(p[1], str) and p[1].isalpha():
                p[0] = ASTNode('identifier', value=p[1], lineno=p.lineno(1))
            else:
                p[0] = p[1]
        else:
            p[0] = p[2]
    
    def p_constant(self, p):
        '''constant : NUMBER
                   | CHAR_LITERAL'''
        p[0] = ASTNode('constant', value=p[1], lineno=p.lineno(1))
    
    def p_string(self, p):
        '''string : STRING_LITERAL'''
        p[0] = ASTNode('string_literal', value=p[1], lineno=p.lineno(1))
    
    def p_argument_expression_list(self, p):
        '''argument_expression_list : assignment_expression
                                   | argument_expression_list COMMA assignment_expression'''
        if len(p) == 2:
            p[0] = ASTNode('argument_expression_list', [p[1]], lineno=p.lineno(1))
        else:
            p[1].add_child(p[3])
            p[0] = p[1]
    
    # Simplified grammar rules for other constructs
    def p_unary_operator(self, p):
        '''unary_operator : AND
                         | TIMES
                         | PLUS
                         | MINUS
                         | NOT
                         | LNOT'''
        p[0] = ASTNode('unary_operator', value=p[1], lineno=p.lineno(1))
    
    def p_assignment_operator(self, p):
        '''assignment_operator : ASSIGN
                              | TIMESEQUAL
                              | DIVEQUAL
                              | MODEQUAL
                              | PLUSEQUAL
                              | MINUSEQUAL
                              | LSHIFTEQUAL
                              | RSHIFTEQUAL
                              | ANDEQUAL
                              | XOREQUAL
                              | OREQUAL'''
        p[0] = ASTNode('assignment_operator', value=p[1], lineno=p.lineno(1))
    
    # Simplified rules for missing constructs
    def p_struct_or_union_specifier(self, p):
        '''struct_or_union_specifier : STRUCT ID'''
        p[0] = ASTNode('struct_specifier', value=p[2], lineno=p.lineno(1))
    
    def p_enum_specifier(self, p):
        '''enum_specifier : ENUM ID'''
        p[0] = ASTNode('enum_specifier', value=p[2], lineno=p.lineno(1))
    
    def p_typedef_name(self, p):
        '''typedef_name : ID'''
        p[0] = ASTNode('typedef_name', value=p[1], lineno=p.lineno(1))
    
    def p_type_qualifier_list(self, p):
        '''type_qualifier_list : type_qualifier'''
        p[0] = ASTNode('type_qualifier_list', [p[1]], lineno=p.lineno(1))
    
    def p_constant_expression(self, p):
        '''constant_expression : conditional_expression'''
        p[0] = p[1]
    
    def p_parameter_type_list(self, p):
        '''parameter_type_list : parameter_list'''
        p[0] = p[1]
    
    def p_parameter_list(self, p):
        '''parameter_list : parameter_declaration'''
        p[0] = ASTNode('parameter_list', [p[1]], lineno=p.lineno(1))
    
    def p_parameter_declaration(self, p):
        '''parameter_declaration : declaration_specifiers declarator
                                | declaration_specifiers'''
        if len(p) == 3:
            p[0] = ASTNode('parameter_declaration', [p[1], p[2]], lineno=p.lineno(1))
        else:
            p[0] = ASTNode('parameter_declaration', [p[1]], lineno=p.lineno(1))
    
    def p_identifier_list(self, p):
        '''identifier_list : ID'''
        p[0] = ASTNode('identifier_list', [ASTNode('identifier', value=p[1], lineno=p.lineno(1))], lineno=p.lineno(1))
    
    def p_type_name(self, p):
        '''type_name : specifier_qualifier_list'''
        p[0] = p[1]
    
    def p_specifier_qualifier_list(self, p):
        '''specifier_qualifier_list : type_specifier'''
        p[0] = ASTNode('specifier_qualifier_list', [p[1]], lineno=p.lineno(1))
    
    def p_initializer(self, p):
        '''initializer : assignment_expression'''
        p[0] = p[1]
    
    def p_declaration_list(self, p):
        '''declaration_list : declaration'''
        p[0] = ASTNode('declaration_list', [p[1]], lineno=p.lineno(1))
    
    def p_labeled_statement(self, p):
        '''labeled_statement : ID COLON statement'''
        p[0] = ASTNode('labeled_statement', [p[3]], value=p[1], lineno=p.lineno(1))
    
    def p_selection_statement(self, p):
        '''selection_statement : IF LPAREN expression RPAREN statement'''
        p[0] = ASTNode('if_statement', [p[3], p[5]], lineno=p.lineno(1))
    
    def p_iteration_statement(self, p):
        '''iteration_statement : WHILE LPAREN expression RPAREN statement'''
        p[0] = ASTNode('while_statement', [p[3], p[5]], lineno=p.lineno(1))
    
    def p_jump_statement(self, p):
        '''jump_statement : RETURN SEMICOLON
                         | RETURN expression SEMICOLON'''
        if len(p) == 3:
            p[0] = ASTNode('return_statement', lineno=p.lineno(1))
        else:
            p[0] = ASTNode('return_statement', [p[2]], lineno=p.lineno(1))
    
    def p_error(self, p):
        if p:
            print(f"Syntax error at token {p.type} ('{p.value}') at line {p.lineno}")
        else:
            print("Syntax error at EOF")
    
    def build(self, **kwargs):
        """Build the parser"""
        self.parser = yacc.yacc(module=self, **kwargs)
        return self.parser
    
    def parse(self, input_text, **kwargs):
        """Parse input text and return AST"""
        if not self.parser:
            self.build()
        self.ast = self.parser.parse(input_text, lexer=self.lexer.lexer, **kwargs)
        return self.ast
