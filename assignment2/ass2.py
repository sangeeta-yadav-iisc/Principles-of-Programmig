import sys
from triton import *
Triton=TritonContext()
astc=Triton.getAstContext()
symchar=[]

def run(pc,Target,seed):
    while pc:
	opcodes = Triton.getConcreteMemoryAreaValue(pc, 16)
        inst = Instruction()
        inst.setOpcode(opcodes)
        inst.setAddress(pc)
        Triton.processing(inst)

	if inst.getType()== OPCODE.INT :
                if Triton.getConcreteRegisterValue(Triton.registers.eax)==1:
                     break
                pc=pc+2
                continue

        if inst.getType() == OPCODE.HLT:
		break
        #next  
        pc = Triton.getConcreteRegisterValue(Triton.registers.eip)
        if pc==Target :
           #del seed[1879048195]
           for i in range(500,1500):
               if seed.has_key(i):
                  print chr(seed[i]),
               #else :
                  #print 'a',
               if (i+1)%100==0 :
                  print"\n",
                  
           sys.exit(0)
        pc = Triton.buildSymbolicRegister(Triton.registers.eip).evaluate()
    return



def getNewInput():
    # Set of new inputs
    inputs = list()

    # Get path constraints from the last execution
    pco = Triton.getPathConstraints()

    # Get the astContext
    astCtxt = Triton.getAstContext()

    # We start with any input. T (Top)
    previousConstraints = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue())

    # Go through the path constraints
    for pc in pco:
        # If there is a condition
        if pc.isMultipleBranches():
            # Get all branches
            branches = pc.getBranchConstraints()
            for branch in branches:
                # Get the constraint of the branch which has been not taken
                if branch['isTaken'] == False:
                    # Ask for a model
                    models = Triton.getModel(astCtxt.land([previousConstraints, branch['constraint']]))
                    seed   = dict()
                    for k, v in models.items():
                        # Get the symbolic variable assigned to the model
                        symVar = Triton.getSymbolicVariableFromId(k)
                        # Save the new input as seed.
                        seed.update({symVar.getKindValue(): v.getValue()})
                    if seed:
                        inputs.append(seed)

        # Update the previous constraints with true branch to keep a good path.
        previousConstraints = astCtxt.land([previousConstraints, pc.getTakenPathConstraintAst()])

    # Clear the path constraints to be clean at the next execution.
    Triton.clearPathConstraints()

    return inputs

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

def symbolise(seed,ebpi):
    del symchar[:]
    Triton.concretizeAllRegister()
    Triton.concretizeAllMemory()
    argc=Triton.convertMemoryToSymbolicVariable(MemoryAccess((ebpi+8), CPUSIZE.WORD))
    ##print ebpi+4
    Triton.setConcreteMemoryValue(MemoryAccess(ebpi+12,CPUSIZE.WORD),100)
    for i in range(1, 10):
         Triton.setConcreteMemoryValue(MemoryAccess(100+i*4,CPUSIZE.WORD),500+(i-1)*100)
    for i in range(500, 1500):
         symchar.append(Triton.convertMemoryToSymbolicVariable(MemoryAccess(i, CPUSIZE.BYTE)))
    for address, value in seed.items():
	Triton.setConcreteMemoryValue(MemoryAccess(address,CPUSIZE.WORD),value)
        Triton.convertMemoryToSymbolicVariable(MemoryAccess(address, CPUSIZE.WORD))
    return

if __name__ == '__main__':
   #Define architecture
   Triton.setArchitecture(ARCH.X86)
   
   # Symbolic optimization
   Triton.enableMode(MODE.ALIGNED_MEMORY, True)   

   binary = sys.argv[1]
   # Load the binary
   loadBinary(binary)
   #address for execution
   #ENTRY = 0x080483db
   ENTRY = int(sys.argv[2],16)
   Target =int(sys.argv[3],16)
   #address of istruction to be found
   ##fadd = sys.argv[3]
       
   Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x6fffffff-4)
   Triton.setConcreteRegisterValue(Triton.registers.esp, 0x6fffffff)
   
   ebpi=Triton.getConcreteRegisterValue(Triton.registers.ebp)
   
   
   lastInput = list()
   worklist  = list([{1000:1}])

   while worklist:
        # Take the first seed
        seed = worklist[0]

         
        Triton.setConcreteRegisterValue(Triton.registers.ebp, 0x6fffffff-4)
        Triton.setConcreteRegisterValue(Triton.registers.esp, 0x6fffffff)
       
        symbolise(seed,ebpi)

        # Emulate
        run(ENTRY,Target,seed)
      
       
        lastInput += [dict(seed)]
        del worklist[0]

        newInputs = getNewInput()
        for inputs in newInputs:
            if inputs not in lastInput and inputs not in worklist:
                worklist += [dict(inputs)]

sys.exit(0)
   
