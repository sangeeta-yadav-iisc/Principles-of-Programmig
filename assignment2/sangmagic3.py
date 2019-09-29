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
        
        Triton.convertMemoryToSymbolicVariable(MemoryAccess(esp+8, CPUSIZE.DWORD))
        Triton.setConcreteMemoryValue(esp+8,0x12)
        Triton.setConcreteRegisterValue(Triton.registers.edi, esp+8)
        address=328
        addressv=0x5800
        Triton.setConcreteMemoryValue(MemoryAccess(esp+12,CPUSIZE.WORD),address) 
                
        for i in range(10):
            Triton.setConcreteMemoryValue(MemoryAccess(address,CPUSIZE.WORD),addressv)
            address=address+4             
            for j in range(100):
               
               Triton.convertMemoryToSymbolicVariable(MemoryAccess(addressv, CPUSIZE.WORD))
               Triton.setConcreteMemoryValue(addressv,0x12)
               addressv=addressv+1       
        for address, value in seed.items():   
                Triton.setConcreteMemoryValue(MemoryAccess(address,CPUSIZE.DWORD),value)
                #Triton.setConcreteMemoryValue(address,value)
		Triton.convertMemoryToSymbolicVariable(MemoryAccess(address, CPUSIZE.WORD))
                #Triton.setConcreteMemoryValue(MemoryAccess(address,CPUSIZE.DWORD),value)    
                Triton.convertMemoryToSymbolicVariable(MemoryAccess(address+1, CPUSIZE.WORD))
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
        if instruction.getType()== OPCODE.INT :
                if Triton.getConcreteRegisterValue(Triton.registers.eax)==1:
                     break
                pc=pc+2
                continue

        if instruction.getType() == OPCODE.HLT:
		break
        
        pc = Triton.buildSymbolicRegister(Triton.registers.eip).evaluate()
        
        if sys.argv[3].startswith("0x"): 
            target = int(sys.argv[3][2:],16)
            #print 'target',target
        i=1
        
        if pc == target:
               #printoutput() 
               '''for address, value in seed.items(): 
                    #print 'address',address 
                    print chr(value)
                    if(address==1879048195):  
                          print 'argc ',value
                    else: 
                          x=address-22528
                          y=int(x/100)
                          z=int(x%100)                
                          print 'argv[',y,'][',z,'] ',value
                          i=i+1'''                
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
        #print '[+] Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size)
        Triton.setConcreteMemoryAreaValue(vaddr, phdr.content)
    return binary
def printoutput():
    address=328
    addressv=0x5800
    for i in range(10):
            Triton.setConcreteMemoryValue(MemoryAccess(address,CPUSIZE.WORD),addressv)
            address=address+4             
            for j in range(100):
               
               Triton.convertMemoryToSymbolicVariable(MemoryAccess(addressv, CPUSIZE.WORD))
               Triton.setConcreteMemoryValue(addressv,0x12)
               addressv=addressv+1

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
                        #Triton.convertMemoryToSymbolicVariable(MemoryAccess(k, CPUSIZE.DWORD))
		        #Triton.convertMemoryToSymbolicVariable(MemoryAccess(k+1, CPUSIZE.DWORD))
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
    Triton.enableMode(MODE.ALIGNED_MEMORY, True)
    Triton.enableMode(MODE.ONLY_ON_SYMBOLIZED, True)    
    Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x6ffffffb)
    Triton.setConcreteRegisterValue(Triton.registers.esp, 0x6fffffff)
    Triton.setConcreteRegisterValue(Triton.registers.edi, 0x10000000)
    lastInput = list()
    worklist  = list([{0x70000003:1}])
    while worklist:
        seed = worklist[0]      
        del worklist[0]  
        symbolizeInputs(seed,w)
        #initContext()
        if sys.argv[2].startswith("0x"): # base 16
            entry = int(sys.argv[2][2:],16)
        w=emulate(entry,w)       
        if w==11:            
            symbolizeInputs(seed,w)
            break'''      
        lastInput += [dict(seed)]
        if w==11:            
            print lastInput  
            for items in lastInput:
                for key in items:
                    print dict(key)
        newInputs = getNewInput()
        
        for inputs in newInputs:
             if inputs not in lastInput and inputs not in worklist:
                worklist += [dict(inputs)]
                
    sys.exit(0)
