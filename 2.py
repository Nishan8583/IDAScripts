from idautils import *
from idaapi import *
from idc import *
from source import *

print("--SCRIPT STARTED--")

# Get list of segments available
segAddressList = Segments()


# addFunctionCallLimit checks if the call instruction has any function that was in functionCallsCountLimit
# If so the function is addded numberOfFunctionCalls, and the number of time it appears, the count is updated 
def addFunctionCallLimit(disassembly):
    for key, value in functionCallsCountLimit.iteritems():
        if key in disassembly:
            try:
                numberOfFunctionCalls[key] = numberOfFunctionCalls[key] + 1
            except KeyError:
                numberOfFunctionCalls[key] = 0

# The function checks if the founction call count limit was reached
def checkIfLimitCrossed():
    for key, value in numberOfFunctionCalls.iteritems():
        if value > functionCallsCountLimit[key]:
            print("Higher number of function calls for function {} limit is {} observed count is {}".format(key,functionCallsCountLimit[key],value))

# check if function present
def checkIfInList(techniqueName, techniqueList, address, disassembly, message):
    for technique in techniqueList:
        if technique.lower() in disassembly.lower():
             print(message)

# jump lists
jumpLists = ["jmp","jnz","jbe","jge","jz"]

# checking if the jump is to itself
def checkInvalidJump(disassembly):
    peekAddr = next_head(nextInstruction,endAddr)
    disList = disassembly.split("     ")
    print(disList)

def checkIfResolvedNames():
    #disList = disassembly.split("     ")
    
    for name in function_list:
        if name in disassembly:
            return
    
    for name in nameList:
        if name in disassembly:
            return
    print("THe function was not in resolved lists",disassembly)                

def checkIfJumpAtSameAddress():

    # Looping through jump lists
    for jumps in jumpLists:

        # checking if it is a jump instruction
        if jumps in disassembly:

            # seperating jump code and address
            disList1 = disassembly.split("     ")

            # getting the next address
            peekAddr = next_head(nextInstruction,endAddr)

            # Getting the next instruction
            peekInst = GetDisasm(peekAddr)

            for jumps2 in jumpLists:

                # Checking if the next instruction is also jump
                if jumps2 in peekInst:
                    disList2 = peekInst.split("     ")
                    if disList1[1] == disList2[1]:  # If both consequtive jumps was at same address
                        print("There is jump at same address")



# loop through all sections
for address in segAddressList:

    # If .text section was found
    if get_segm_name(address) == ".text":
        print("GOT THE TEXT SECTION")

        # Get the start and end address of the segment
        nextInstruction = address
        
        # Get end address of the segment
        endAddr = get_segm_end(address)

        while nextInstruction <= endAddr:

            # Get the disassembly 
            disassembly = GetDisasm(nextInstruction)

            # If call present in the disassembly
            if "call" in disassembly:

                # Calling checkAntiAnalysis Function
                checkIfInList("covert-launching", covertLaunchingFunctionCalls, nextInstruction, disassembly, 
                "[*] Possible covert launching Technique at {} -> {}\n".format(hex(int(address)),disassembly))

                checkIfInList("Anti Re", antiREFunctionCalls, nextInstruction, disassembly, 
                "[*] Possible Anti RE Technique at {} -> {}\n".format(hex(int(address)),disassembly))

                checkIfInList("Anti Debug",antiDebugFunctionCalls , nextInstruction, disassembly, 
                "[*] Possible Anti Debug Technique at {} -> {}\n".format(hex(int(address)),disassembly))

                checkIfInList("Anti VM", antiVMFunctionCalls, nextInstruction, disassembly, 
                "[*] Possible Anti VM Technique at {} -> {}\n".format(hex(int(address)),disassembly))

                # Checking funciton limit
                addFunctionCallLimit(disassembly)
                checkIfJumpAtSameAddress()
                checkIfResolvedNames()
            if "xor" in disassembly:
                print(disassembly)

            #if "jmp" in disassembly:
            #    checkInvalidJump(disassembly)
            # Increasing the address, so that we can check the next instruction    
            nextInstruction = next_head(nextInstruction,endAddr)
        
        # Checking funciton limit
        checkIfLimitCrossed()

        print("--Text Section analysis finished, Now exiting--")

