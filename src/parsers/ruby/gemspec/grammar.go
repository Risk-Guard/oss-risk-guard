package gemspec

import (
	"github.com/alecthomas/participle/v2/lexer"
)

var rubyLexer = lexer.MustStateful(lexer.Rules{
	"Root": {
		{Name: "HeredocStart", Pattern: `<<[-~]?(\w+)\n`, Action: lexer.Push("Heredoc")},
		{Name: "HeredocStartDQ", Pattern: `<<[-~]?"(\w+)"\n`, Action: lexer.Push("Heredoc")},
		{Name: "HeredocStartSQ", Pattern: `<<[-~]?'(\w+)'\n`, Action: lexer.Push("Heredoc")},
		{Name: "HeredocStartBT", Pattern: "<<[-~]?`(\\w+)`\\n", Action: lexer.Push("Heredoc")},
		{Name: "Comment", Pattern: `#[^\n]*`},
		{Name: "DoubleColon", Pattern: `::`},
		{Name: "Symbol", Pattern: `:[a-zA-Z_][a-zA-Z0-9_]*`},
		{Name: "PercentLiteral", Pattern: `%[wWiIqQxrs]?\[[^\]]*\]|%[wWiIqQxrs]\{[^}]*\}`},
		{Name: "Backtick", Pattern: "`(?:[^`\\\\]|\\\\.)*`"},
		{Name: "SingleString", Pattern: `'(?:[^'\\]|\\.)*'`},
		{Name: "DoubleString", Pattern: `"(?:[^"\\]|\\.)*"`},
		{Name: "RegexLiteral", Pattern: `/(?:[^/\\]|\\.)+/[imxo]*`},
		{Name: "GlobalVar", Pattern: `\$[a-zA-Z0-9_]+`},
		{Name: "Ident", Pattern: `[a-zA-Z_][a-zA-Z0-9_]*[?!]?`},
		{Name: "Number", Pattern: `\d+`},
		{Name: "Operator", Pattern: `\+|-|\*\*|\*|/|%|==|!=|<=|>=|=~|!~|<|>|&&|&|\|\||\|`},
		{Name: "Punct", Pattern: `[()[\]{},=.|:]`},
		{Name: "Whitespace", Pattern: `[ \t\n\r]+`},
		{Name: "Unknown", Pattern: `.`},
	},
	"Heredoc": {
		{Name: "HeredocEnd", Pattern: `[ \t]*\1[ \t]*(?:\n|$)`, Action: lexer.Pop()},
		{Name: "HeredocLine", Pattern: `[^\n]*\n`},
	},
})
