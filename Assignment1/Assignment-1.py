import triton
import sys
from triton import *


def debug(str):
    print "[+] "+ str

def emulate(pc):
    print '[+] Starting emulation.'
    while pc:
    
    return



def loadBinary(binary):

    raw    = binary.getRaw()
    phdrs  = binary.getProgramHeaders()
    for phdr in phdrs:
        offset = phdr.getOffset()
        size   = phdr.getFilesz()
        vaddr  = phdr.getVaddr()
        print '[+] Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size)
        setConcreteMemoryAreaValue(vaddr, raw[offset:offset+size])
    return





if __name__ == '__main__':
    # Define the target architecture
    setArchitecture(ARCH.X86)


    binary = Elf(sys.argv[1])
    # Load the binary
    loadBinary(binary)

    setConcreteRegisterValue(Register(REG.EBP, 0x7fffffff))
    setConcreteRegisterValue(Register(REG.ESP, 0x6fffffff))

    print emulate(0x080484BB)

    sys.exit(0)
