import triton
import sys
from triton import *
from triton.ast import *

#argv=list()
def symbolizeInputs(seed,w):
        concretizeAllRegister()
        concretizeAllMemory()    
        
        setConcreteRegisterValue(Register(REG.EBP, 0x6ffffffb))
        setConcreteRegisterValue(Register(REG.ESP, 0x6fffffff))
        #setConcreteRegisterValue(Register(REG.EDI, 0x1000))
        esp=getConcreteRegisterValue(REG.EBP)
        convertMemoryToSymbolicVariable(MemoryAccess(esp+8, CPUSIZE.DWORD,0x12))
        setConcreteRegisterValue(Register(REG.EDI, esp+8))
        address=328
        addressv=0x5800
        setConcreteMemoryValue(MemoryAccess(esp+12,CPUSIZE.WORD,address))
        
        for i in range(10):
            setConcreteMemoryValue(MemoryAccess(address,CPUSIZE.WORD,addressv))
            address=address+4 
            #print "address",address    
            for j in range(100):
               convertMemoryToSymbolicVariable(MemoryAccess(addressv, CPUSIZE.DWORD,0x12))
               addressv=addressv+1
               #print "addressv",addressv
       
        for address, value in seed.items():       
		convertMemoryToSymbolicVariable(MemoryAccess(address, CPUSIZE.DWORD, value))
		#convertMemoryToSymbolicVariable(MemoryAccess(address+1, CPUSIZE.DWORD)) 
                #l=getConcreteMemoryValue (0x70000003L)       
        return

def printargv():
     address=328
     addressv=0x5800
     for i in range(10):            
            address=address+4
            #print "\n",'argv{}'.format(i),
            for j in range(100):
               #print getConcreteMemoryValue(MemoryAccess(addressv, CPUSIZE.DWORD)),
               addressv=addressv+1
     i=i+1

def emulate(pc,w):
    while pc:        
        opcodes = getConcreteMemoryAreaValue(pc, 16)
        instruction = Instruction()
        instruction.setOpcodes(opcodes)
        instruction.setAddress(pc)
        processing(instruction)
        pc = getConcreteRegisterValue(REG.EIP)
        if sys.argv[3].startswith("0x"): 
            target = int(sys.argv[3][2:],16)
        i=1
        if pc== target:
               print '=======================================Address found with following seeds================================================'  
               for address, value in seed.items(): 
                    ##print '[+] Symbolic variable at {} = {} ' .format(hex(address), value)
                    #if(address==1879048195):
                    if(address==1879048195):  
                          print 'argc ',value
                    else: 
                          x=address-22528
                          y=int(x/100)
                          z=int(x%100)
                 
                          print 'argv[',y,'][',z,'] ',value
                          i=i+1  
               '''for s in range(i,11):
                    print 'argv [',s,']',0 
                    s=s+1'''     
               w=11
               break
    #print '[+] Emulation done.'
    return w

def printer(worklist):
    for i in worklist:
	for k,v in i.iteritems():
	    print ("key: ", hex(k) , "Value:" , v)

def loadBinary(binary):
    raw    = binary.getRaw()
    phdrs  = binary.getProgramHeaders()
    for phdr in phdrs:
        offset = phdr.getOffset()
        size   = phdr.getFilesz()
        vaddr  = phdr.getVaddr()
        setConcreteMemoryAreaValue(vaddr, raw[offset:offset+size])
    return

def getNewInput():
    inputs = list()
    pco = getPathConstraints()
    previousConstraints = equal(bvtrue(), bvtrue())
    for pc in pco:
        if pc.isMultipleBranches():        
            branches = pc.getBranchConstraints()
            for branch in branches:
                if branch['isTaken'] == False:
                    models = getModel(assert_(land(previousConstraints, branch['constraint'])))
                    seed   = dict()
                    for k, v in models.items():
                        symVar = getSymbolicVariableFromId(k)
                        seed.update({symVar.getKindValue(): v.getValue()})
                        convertMemoryToSymbolicVariable(MemoryAccess(k, CPUSIZE.DWORD))
		        convertMemoryToSymbolicVariable(MemoryAccess(k+1, CPUSIZE.DWORD))
                    if seed:
                        inputs.append(seed)    
        previousConstraints = land(previousConstraints, pc.getTakenPathConstraintAst())   
    clearPathConstraints()
    return inputs
w=0

if __name__ == '__main__':  
    setArchitecture(ARCH.X86)
    binary = Elf(sys.argv[1])
    loadBinary(binary)#this is to laod the binary
    enableMode(MODE.ALIGNED_MEMORY, True)
    enableMode(MODE.ONLY_ON_SYMBOLIZED, True)
    setConcreteRegisterValue(Register(REG.EBP, 0x6ffffffb))
    setConcreteRegisterValue(Register(REG.ESP, 0x6fffffff))
    setConcreteRegisterValue(Register(REG.EDI, 0x10000000))
    lastInput = list()
    worklist  = list([{0x70000003:1}])
    while worklist:
        seed = worklist[0]
        #print "seed",seed
        del worklist[0]  
        
        symbolizeInputs(seed,w)
        if sys.argv[2].startswith("0x"): # base 16
            entry = int(sys.argv[2][2:],16)
        w=emulate(entry,w)
        if w==11:
            #printargv()
            symbolizeInputs(seed,w)
            break      
        #else:
        #    print "wait"
        lastInput += [dict(seed)]
        newInputs = getNewInput()
        #print "newInputs",newInputs
        for inputs in newInputs:
             if inputs not in lastInput and inputs not in worklist:
                worklist += [dict(inputs)]
                #print "worklist",worklist
    sys.exit(0)
