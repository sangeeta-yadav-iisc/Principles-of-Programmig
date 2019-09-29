import triton
import sys
import string
from triton import *
from triton import ARCH, TritonContext, MemoryAccess, CPUSIZE, Instruction, MODE, CALLBACK
import lief
Triton = TritonContext()

def emulate(pc,index,y,targetadd):
    Triton.concretizeAllRegister()
    Triton.concretizeAllMemory() 
    flag=0
    Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x6ffffffb)
    Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x6fffffff)
    esp=Triton.buildSymbolicRegister(Triton.registers.ebp).evaluate()
    address=28
    addressv=200
    Triton.setConcreteMemoryValue(esp+12,address)
    Triton.setConcreteMemoryValue(address,addressv)

    for i in range(index+1):
         Triton.setConcreteMemoryValue(addressv,ord('S'))
         addressv=addressv+1
    if (y==1):
         #strin= ""
         for j in range(index):
              print 'F'
              #strin = strin+'F'
         #print strin,hex(targetadd)
         print hex(targetadd)
    while pc:
        opcodes = Triton.getConcreteMemoryAreaValue(pc, 16)
        instruction = Instruction()
        instruction.setOpcode(opcodes)
        instruction.setAddress(pc)
        Triton.processing(instruction)
       
        if (instruction.isControlFlow()):
                flag = flag+1	
	
        if instruction.getType() == OPCODE.INT:
                pc = instruction.getNextAddress()
                y = Triton.buildSymbolicRegister(Triton.registers.eax).evaluate()
                if y == 1:
                	break
                continue
        pc = Triton.buildSymbolicRegister(Triton.registers.eip).evaluate()
     
        if (pc == 28) :
                
                return 5
    
    return 1

def loadBinary(path):
    import lief
    binary = lief.parse(path)
    phdrs  = binary.segments
    for phdr in phdrs:
        size   = phdr.physical_size
        vaddr  = phdr.virtual_address
        Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
    return binary


if __name__ == '__main__': 
    Triton = TritonContext() 
    Triton.setArchitecture(ARCH.X86)
   
    binary = loadBinary(sys.argv[1])
   
    Triton.enableMode(MODE.ALIGNED_MEMORY, True)
    Triton.enableMode(MODE.ONLY_ON_SYMBOLIZED, True)
    
    Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x6ffffffb)
    Triton.setConcreteRegisterValue(Triton.registers.esp, 0x6fffffff)
    Triton.setConcreteRegisterValue(Triton.registers.edi, 0x10000000)
    if sys.argv[2].startswith("0x"): 
            entry = int(sys.argv[2][2:],16)
            targetadd = int(sys.argv[3][2:],16)
    flag=0
    for i in range(100000):
       w=emulate(entry,i,0,targetadd)
       if w==5 :
            flag=1
            emulate(entry,i,1,targetadd)
            sys.exit(0)
    sys.exit(0)
