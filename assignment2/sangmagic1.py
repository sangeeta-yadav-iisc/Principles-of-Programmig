import triton
import sys
import string
from triton import *
from triton import ARCH, TritonContext, MemoryAccess, CPUSIZE, Instruction, MODE, CALLBACK
import lief

def symbolizeInputs(seed,w):
        Triton.concretizeAllRegister()
        Triton.concretizeAllMemory()            
        Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x6ffffffb)
        Triton.setConcreteRegisterValue(Triton.registers.esp, 0x6fffffff)       
        esp=Triton.getConcreteRegisterValue(Triton.registers.ebp)       
        Triton.setConcreteMemoryValue(esp+8,0x12)
        Triton.convertMemoryToSymbolicVariable(MemoryAccess(esp+8, CPUSIZE.DWORD))
        Triton.setConcreteRegisterValue(Triton.registers.edi, esp+8)
        address=328
        addressv=0x5800
        Triton.setConcreteMemoryValue(MemoryAccess(esp+12,CPUSIZE.WORD),address) 
                
        for i in range(3):
            Triton.setConcreteMemoryValue(MemoryAccess(address,CPUSIZE.WORD),addressv)
            address=address+4             
            for j in range(100):
               #temp=int(0x0804840b)
               #string = 0x08#Byte.toString((byte)temp)
               Triton.setConcreteMemoryValue(addressv,0x12)
               Triton.convertMemoryToSymbolicVariable(MemoryAccess(addressv, CPUSIZE.DWORD))
               addressv=addressv+1       
        for address, value in seed.items():   
                Triton.setConcreteMemoryValue(MemoryAccess(address,CPUSIZE.DWORD),value)    
		Triton.convertMemoryToSymbolicVariable(MemoryAccess(address, CPUSIZE.DWORD))
                #Triton.convertMemoryToSymbolicVariable(MemoryAccess(address+1, CPUSIZE.DWORD))
        return

def emulate(pc,w):
    while pc: 
        #print 'pc1',pc       
        opcodes = Triton.getConcreteMemoryAreaValue(pc, 16)
        #print 'opcodes',opcodes
        instruction = Instruction()
        instruction.setOpcode(opcodes)
        instruction.setAddress(pc)
        Triton.processing(instruction)      
        #pc = hex(eip.evaluate())
        pc=Triton.getConcreteRegisterValue(Triton.registers.eip)
        if sys.argv[3].startswith("0x"): 
            target = int(sys.argv[3][2:],16)
            #print 'target',target
        i=1
        
        if pc == target:
               print '==================Address found with following seeds============='  
               for address, value in seed.items(): 
                    if(address==1879048195):  
                          print 'argc ',value
                    else: 
                          x=address-22528
                          y=int(x/100)
                          z=int(x%100)                
                          print 'argv[',y,'][',z,'] ',value
                          i=i+1                 
               w=11
               break   
    return w

def loadBinary(path):
    import lief
    binary = lief.parse(path)
    phdrs  = binary.segments
    for phdr in phdrs:
        size   = phdr.physical_size
        vaddr  = phdr.virtual_address
        print '[+] Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size)
        Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
    return binary


def getNewInput():
    inputs = list()
    pco = Triton.getPathConstraints()
    #print 'pco',pco
    astCtxt = Triton.getAstContext()
    previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue())
    for pc in pco:
        if pc.isMultipleBranches():        
            branches = pc.getBranchConstraints()
            for branch in branches:
                if branch['isTaken'] == False:
                    models = Triton.getModel(astCtxt.land([previousConstraints, branch['constraint']]))
                    seed   = dict()
                    for k, v in models.items():
                        symVar = Triton.getSymbolicVariableFromId(k)
                        seed.update({symVar.getKindValue(): v.getValue()})
                        Triton.convertMemoryToSymbolicVariable(MemoryAccess(k, CPUSIZE.DWORD))
		        Triton.convertMemoryToSymbolicVariable(MemoryAccess(k+1, CPUSIZE.DWORD))
                    if seed:
                        inputs.append(seed)    
        previousConstraints = astCtxt.land([previousConstraints, pc.getTakenPathConstraintAst()])   
    Triton.clearPathConstraints()
    return inputs
w=0

if __name__ == '__main__': 
    Triton = TritonContext() 
    Triton.setArchitecture(ARCH.X86)    
    binary = loadBinary(sys.argv[1]) 
    # makeRelocation(binary)  
    Triton.enableMode(MODE.ALIGNED_MEMORY, True)
    Triton.enableMode(MODE.ONLY_ON_SYMBOLIZED, True)    
    Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x6ffffffb)
    Triton.setConcreteRegisterValue(Triton.registers.esp, 0x6fffffff)
    Triton.setConcreteRegisterValue(Triton.registers.edi, 0x10000000)
    lastInput = list()
    worklist  = list([{0x70000007:1}])#{0x7000000f:0x41},{0x700000b4:0x41},{0x700000b8:0x41},{0x70000003:0x41},{0x700000bc:0x0b},{0x700000c1:0x84},{0x700000c5:0x04},{0x700000c9:0x08}])
    #hookingHandler()
    while worklist:
        seed = worklist[0]      
        del worklist[0]  
        symbolizeInputs(seed,w)
        if sys.argv[2].startswith("0x"): # base 16
            entry = int(sys.argv[2][2:],16)
        #Triton.convertRegisterToSymbolicVariable(Triton.registers.eip)
        #eip=Triton.buildSymbolicRegister(Triton.registers.eip)
        w=emulate(entry,w)       
        if w==11:            
            symbolizeInputs(seed,w)
            break      
        lastInput += [dict(seed)]
        newInputs = getNewInput()
        
        for inputs in newInputs:
             if inputs not in lastInput and inputs not in worklist:
                worklist += [dict(inputs)]
                
    sys.exit(0)
