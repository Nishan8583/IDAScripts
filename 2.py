import idautils,idaapi,idc

print("--SCRIPT STARTED--")

# Get list of segments available
segAddressList = idautils.Segments()

# Functions that may be used while malware is trying to run covertly
covertLaunchingFunctionCalls = ["createprocess","openprocess","writeprocess","virtualallocex","createremotethread",
                             "zwunmapviewofsection","SetWindowsHook","QueueUserAPC"]

# List of antidebug techniques
antiDebugFunctionCalls = ["IsDebuggerPresent","OutputDebugStringW","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
                       "ZwQueryInformationProcess","OutputDebugString",]

# List of antiVM techniques
antiVMFunctionCalls = ["IsProcessorFeaturePresent"]

# List of antiRE techniques
antiREFunctionCalls = []

# anti VM instructions
antiVMTechniques = ["sidt","sgdt","sldt","cpuid",]
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
def checkIfInList(techniqueName, techniqueList, address, disassembly, message):
    for technique in techniqueList:
        if technique.lower() in disassembly.lower():
             print(message)

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
            disassembly = idc.GetDisasm(nextInstruction)

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

            # Increasing the address, so that we can check the next instruction    
            nextInstruction = idc.next_head(nextInstruction,endAddr)
        
        # Checking funciton limit
        checkIfLimitCrossed()

        print("--Text Section analysis finished, Now exiting--")