import idautils,idaapi,idc

print("--SCRIPT STARTED--")

# Get list of segments available
segAddressList = idautils.Segments()

# List of antidebug techniques
antiDebugTechniques = ["IsDebuggerPresent","OutputDebugStringW"]

# List of antiVM techniques
antiVMTechniques = ["IsProcessorFeaturePresent"]

# List of antiRE techniques
antiRETechniques = []

# Function Call Count Limit
functionCallsCountLimit = {"GetProcAddress":10}

# functionCalls and their respective count stored
numberOfFunctionCalls = {}

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
def checkAntiAnalysis(option,address,disassembly):

    # Checking anti Debugging techniques
    for functions in antiDebugTechniques:
        if functions in inst:
            print("[*] Possible Anti Debug Technique at {} -> {}".format(hex(int(address)),disassembly))

    # Checking anti vm techniques
    for functions in antiVMTechniques:
        if functions in inst:
            print("[*] Possible Anti VM Technique at {} -> {}".format(hex(int(address)),disassembly))

    for functions in antiRETechniques:
        if functions in inst:
            print("[*] Possible Anti RE Technique at {} -> {}".format(hex(int(address)),disassembly))

# loop through all sections
for address in segAddressList:

    # If .text section was found
    if idc.get_segm_name(address) == ".text":
        print("GOT THE TEXT SECTION")

        # Get the start and end address of the segment
        nextInstruction = address
        
        # Get end address of the segment
        endAddr = idc.get_segm_end(address)

        while nextInstruction <= endAddr:

            # Get the disassembly 
            inst = idc.GetDisasm(nextInstruction)

            # If call present in the disassembly
            if "call" in inst:

                # Calling checkAntiAnalysis Function
                checkAntiAnalysis("anti-debug",nextInstruction,inst)

                # Checking funciton limit
                addFunctionCallLimit(inst)

            # Increasing the address, so that we can check the next instruction    
            nextInstruction = idc.next_head(nextInstruction,endAddr)
        
        # Checking funciton limit
        checkIfLimitCrossed()

        print("--Text Section analysis finished, Now exiting--")