import sys
from triton import *
Triton=TritonContext()
astc=Triton.getAstContext()

def loadBinary(path):
    import lief
    binary = lief.parse(path)
    phdrs  = binary.segments
    for phdr in phdrs:
        size   = phdr.physical_size
        vaddr  = phdr.virtual_address
        print '[+] Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size)
        Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
    return

def symbolize(seed):
        Triton.concretizeAllRegister()
        Triton.concretizeAllMemory()    
        
        Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x6ffffffb) #hardcode default value of EBP
        Triton.setConcreteRegisterValue(Triton.registers.esp, 0x6fffffff) #hardcode default value of ESP
        ebp = Triton.getConcreteRegisterValue(Triton.registers.ebp)
        Triton.convertMemoryToSymbolicVariable(MemoryAccess((ebp+8), CPUSIZE.WORD))
        Triton.setConcreteRegisterValue(Triton.registers.esp, ebp + 8)
        v1=100
        v2=0x2000
        Triton.setConcreteMemoryValue(MemoryAccess(ebp + 12, CPUSIZE.WORD), v1)
        
        for i in range(10): #concretize all values for the 10 inputs to be entered
            Triton.setConcreteMemoryValue(MemoryAccess(v1,CPUSIZE.WORD),v2)
            v1 += 4
            for j in range(100):
               Triton.convertMemoryToSymbolicVariable(MemoryAccess((v2), CPUSIZE.WORD))
               v2 += 1
       
        for v1, value in seed.items():
        	Triton.convertMemoryToSymbolicVariable(MemoryAccess((v1), CPUSIZE.DWORD))        
        return

def emulate(pc,counter):
    while pc:
        opcodes = Triton.getConcreteMemoryAreaValue(pc, 16)
        instruction = Instruction()
        instruction.setOpcode(opcodes)
        instruction.setAddress(pc)
        Triton.processing(instruction)
        pc = Triton.getConcreteRegisterValue(Triton.registers.eip)
        if sys.argv[3].startswith("0x"): 
            final = int(sys.argv[3][2:],16)
        i=1
        if pc == final:
               for address, value in seed.items(): 
                    if(address==0x70000003): 
                          print "At address, ", address,': argc=',value
                    else:
                          print "At address, ", address,': argv=',value
                          i=i+1      
               counter=11
               break
    return counter


def getInput():
    ip = list()
    p_const = Triton.getPathConstraints()
    astcontext = Triton.getAstContext()
    previousConstraints = astcontext.equal(astcontext.bvtrue(), astcontext.bvtrue())
    for p_c in p_const:
        if p_c.isMultipleBranches():        
            branches = p_c.getBranchConstraints()
            for branch in branches:
                if branch['isTaken'] == False:
                    models = Triton.getModel(Triton.assert_(astcontext.land(previousConstraints, branch['constraint'])))
                    seed   = dict()
                    for k, v in models.items():
                        sym_var = Triton.getSymbolicVariableFromId(k)
                        seed.update({sym_var.getKindValue(): v.getValue()})
                        convertMemoryToSymbolicVariable(MemoryAccess(k, CPUSIZE.WORD))
                        convertMemoryToSymbolicVariable(MemoryAccess(k+1, CPUSIZE.WORD))
                    if seed:
                        ip.append(seed)    
        previousConstraints = astcontext.land(previousConstraints, p_c.getTakenPathConstraintAst())   
    Triton.clearPathConstraints()
    return ip

counter=0

if __name__ == '__main__':  
    
    Triton.setArchitecture(ARCH.X86)
    Triton.enableMode(MODE.ALIGNED_MEMORY, True)
    binary = sys.argv[1]
    loadBinary(binary)
    
    Triton.enableMode(MODE.ONLY_ON_SYMBOLIZED, True)
    Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x6ffffffb)
    Triton.setConcreteRegisterValue(Triton.registers.esp, 0x6fffffff)
    #setConcreteRegisterValue(Register(REG.EDI, 0x10000000))
    
    lastInput = list()
    workList  = list([{0x1000:1}])
    
    while workList:
        seed = workList[0]
        del workList[0]  
        
        symbolize(seed)
        
        if sys.argv[2].startswith("0x"):
            ENTRY = int(sys.argv[2][2:],16)
            
        counter = emulate(ENTRY,counter)
        
        if counter == 11:
            symbolize(seed)
            break
            
        lastInput += [dict(seed)]
        newInputs = getInput()
        
        for inputs in newInputs:
             if inputs not in lastInput and inputs not in workList:
                workList += [dict(inputs)]
    sys.exit(0)
