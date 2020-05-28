import idautils,idaapi,idc

print("-------ScriptStarted--------------")
functions = idautils.Names()

for i in functions:
    if i[1] == "start":
        start = i[0]
        startFunc = idaapi.get_func(start)

        while start < startFunc.endEA:
            n = idc.GetMnem(start)
            if n == "call":
                print("There was a call -> {} at address {}".format(idc.GetDisasm(start),start))

            start = idc.next_head(start,startFunc.endEA)

print("Script Ended")
