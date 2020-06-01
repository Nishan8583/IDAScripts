from idautils import *
from idaapi import *
from idc import *
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

# Getting a list of all resolved names
namesGen = Names()
nameList = []

for name in namesGen:
    nameList.append(name[1])

# Getting the funcito names
functions = Functions()
function_list = []
for f in functions:
    function_list.append(GetFunctionName(f))
