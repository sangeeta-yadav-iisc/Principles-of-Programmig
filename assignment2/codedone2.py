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
    x=0
    #Triton.buildSymbolicRegister(Triton.registers.eax).evaluate()
    Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x6ffffffb)
    Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x6fffffff)
    esp=Triton.buildSymbolicRegister(Triton.registers.ebp).evaluate()
    address=28
    addressv=234
    Triton.setConcreteMemoryValue(esp+12,address)
    Triton.setConcreteMemoryValue(address,addressv)
    #Triton.setConcreteMemoryAreaValue(address,CPUSIZE.WORD,addressv)

    #print 'index',index 
    for i in range(index+1):
         #index=index-1
         Triton.setConcreteMemoryValue(addressv,ord('A'))
         #print 'A' 
         addressv=addressv+1
    if (y==1):
         print 'This Input its is going to given/invalid address'
         strin=""
         for j in range(index):
              strin = strin+'A'
         print strin,hex(targetadd) #, type(targetadd)
         #Triton.setConcreteMemoryValue(MemoryAccess(addressv,CPUSIZE.DWORD),targetadd) 
         #inte = int(targetadd[2:3])
         #print unichr(inte)
    #+ targetadd[0]+targetadd[1]+targetadd[2]+targetadd[3]+targetadd[4]+targetadd[5]+targetadd[6]
    
    #Triton.setConcreteMemoryAreaValue(address,CPUSIZE.WORD,addressv)
    while pc:
        # Fetch opcodes
        opcodes = Triton.getConcreteMemoryAreaValue(pc, 16)
        # Create the Triton instruction
        instruction = Instruction()
        instruction.setOpcode(opcodes)
        instruction.setAddress(pc)
        
        # Process
        Triton.processing(instruction)
        #print instruction 

        if (instruction.isControlFlow()):
                x = x+1	
	
        if instruction.getType() == OPCODE.INT:
                pc = instruction.getNextAddress()
                y = Triton.buildSymbolicRegister(Triton.registers.eax).evaluate()
                #y = getConcreteRegisterValue(REG.EAX)
                if y == 1:
                	break
                continue
        # Next
        pc = Triton.buildSymbolicRegister(Triton.registers.eip).evaluate()
        #print pc
        if (pc == 28) :
                #print "reached"
                return 5
    
    #print 'The number of control transfer instructions are :' 
    #print x
    return 1

def loadBinary(path):
    import lief
    binary = lief.parse(path)
    phdrs  = binary.segments
    for phdr in phdrs:
        size   = phdr.physical_size
        vaddr  = phdr.virtual_address
        ##print '[+] Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size)
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
    if sys.argv[2].startswith("0x"): # base 16
            entry = int(sys.argv[2][2:],16)
            targetadd = int(sys.argv[3][2:],16)
    #print 'entry',entry
    #targetadd = sys.argv[3]
    #send targetadd to emulate
    x=0
    for i in range(100000):
       w=emulate(entry,i,0,targetadd)
       if w==5 :
            x=1
            emulate(entry,i,1,targetadd)
            sys.exit(0)
    #getNewInput()
    sys.exit(0)
