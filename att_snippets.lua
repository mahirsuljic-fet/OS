local ls = require("luasnip")
local s = ls.snippet
local t = ls.text_node
local i = ls.insert_node
local f = ls.function_node

local function fn(args)
	return args[1][1]
end

-- BASIC --
ls.add_snippets("asm", {
	s({
		trig = "st",
		name = "start",
	}, {
		t({
			".section .rodata",
			"",
			".section .data",
			"",
			".section .bss",
			"",
			".section .text",
			"",
			".globl _start",
			"_start:",
			"  ",
		}),
		i(0),
		t({
			"  ",
			"  movl $1, %eax",
			"  movl $0, %ebx",
			"  int $0x80",
		}),
	}),
	s({
		trig = "start",
		name = "start",
	}, {
		t({
			".section .rodata",
			"",
			".section .data",
			"",
			".section .bss",
			"",
			".section .text",
			"",
			".globl _start",
			"_start:",
			"  ",
		}),
		i(0),
		t({
			"  ",
			"  movl $1, %eax",
			"  movl $0, %ebx",
			"  int $0x80",
		}),
	}),
	s({
		trig = "print",
		name = "print using system calls",
	}, {
		t({
			"  movl $4, %eax",
			"  movl $1, %ebx",
			"  movl ",
		}),
		i(1),
		t({
			", %ecx",
			"  movl $",
		}),
		i(0),
		t({
			", %edx",
			"  int $0x80",
		}),
	}),
	s({
		trig = "func",
		name = "global function with return",
	}, {
		t(".globl "),
		f(fn, { 1 }),
		t({ "", "" }),
		i(1),
		t({ ":", "  " }),
		i(0),
		t({ "", "  ret" }),
	}),
	s({
		trig = "sstart",
		name = "start function",
	}, {
		t({
			".globl _start",
			"_start:",
			"  ",
		}),
		i(0),
		t({
			"  ",
			"  movl $1, %eax",
			"  movl $0, %ebx",
			"  int $0x80",
		}),
	}),
	s({
		trig = "exit",
		name = "exit",
	}, {
		t({
			"  movl $1, %eax",
			"  movl $0, %ebx",
			"  int $0x80",
		}),
	}),
	s({
		trig = "gll",
		name = "global label",
	}, {
		t(".globl "),
		f(fn, { 1 }),
		t({ "", "" }),
		i(1),
		t({ ": " }),
		i(0),
	}),
	s({
		trig = "stext",
		name = "text section",
	}, {
		t({ ".section .text", "" }),
	}),
	s({
		trig = "sdata",
		name = "data section",
	}, {
		t({ ".section .data", "" }),
	}),
	s({
		trig = "sbss",
		name = "bss section",
	}, {
		t({ ".section .bss", "" }),
	}),
	s({
		trig = "srodata",
		name = "rodata section",
	}, {
		t({ ".section .rodata", "" }),
	}),
})
