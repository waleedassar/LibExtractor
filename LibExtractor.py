import os,sys,time,datetime,struct


def StrReverse(Str):
    return Str[::-1]

def GetNextString(Str,Offset,Length):
    if Str == "":
        return ""
    NewStr = ""
    i = Offset
    while i < Length and Str[i] != "\x00":
        NewStr += Str[i]
        i = i + 1
    return NewStr


def GetNumberOfUniqueElements(ListX):
    NewList = []
    LenListX = len(ListX)
    for i in range(0,LenListX):
        E = ListX[i]
        Found = False
        for ii in range(0,len(NewList)):
            EE = NewList[ii]
            if EE == E:
                Found = True
                break
        if Found == False:
            NewList.append(E)
    return len(NewList)

NumArgs = len(sys.argv)
if NumArgs != 2:
    print "Usage: LibExtractor.py input.lib"
    sys.exit(-1)



inF = sys.argv[1]
if os.path.exists(inF)==False or \
   os.path.getsize(inF)==0:
    sys.exit(-2)
    
fIn = open(inF,"rb")
fCon = fIn.read()
fIn.close()


Magic = fCon[0:8]

if Magic != "!<arch>\n":
    print "Input file is not .Lib file"
    sys.exit(-3)

lenX = len(fCon)
c = 8
Num = 0


Members = []

#The following two lists hold indices
LinkerMembers = [] #Usually they are only two
LongNamesMembers = []  #usually it is only one member and is third member

while c < lenX:
    Header = fCon[c:c+60]
    c += 60
    
    Name = (Header[0:16]).rstrip(" ")
    if Name == "/":
        print "Name: / (Linker Member)"
        LinkerMembers.append(Num)
    elif Name == "//":
        print "Name: // (Long Names Member)"
        LongNamesMembers.append(Num)
    else:
        if Name[0]=="/":
            #Read from the "Long Names" member
            pass
        else:
            print "Name: " + Name
    
    uDate = (Header[16:28]).rstrip(" ")
    Date = datetime.datetime.fromtimestamp(int(uDate))
    print Date
    
    UserId = (Header[28:34]).rstrip(" ")
    if UserId != "":
        print "User Id: " + UserId
    else:
        print "User Id: N/A"

    GroupId = (Header[34:40]).rstrip(" ")
    if GroupId != "":
        print "Group Id: " + GroupId
    else:
        print "Group Id: N/A"

    Mode = (Header[40:48]).rstrip(" ")
    if Mode != "":
        if Mode[0:2]!="0o" and Mode[0:2]!="0O":
            sMode = "0o" + Mode
            iMode = int(sMode,8)
            print "Mode: " + str(iMode)
    else:
        print "Mode: N/A"

    MemberSize = int((Header[48:58]).rstrip(" "))
    print "Member Size: " + str(MemberSize) + " bytes."
    
    EndHdr = Header[58:60]
    if EndHdr != "\x60\x0A":
        print "Invalid Header End"
        
    
    if c + MemberSize <= lenX:
        Mem = fCon[c:c+MemberSize]
        Members.append(Mem)
        Num += 1
        c += MemberSize
    else:
        print "Boundary error"
        break

    #Align
    if c%2 != 0:
        c += 1
    print "----------------------"


c = 0
filename,filext = os.path.splitext(inF)

#Dumping members to disk
print "Now extracting " + str(Num) + " members to disk..."
while c < Num:
    outFileName = filename +"_"+str(c)
    cMem = Members[c]
    Machine = cMem[0:2]
    Extra = cMem[2:4]
    if Machine == "\x4C\x01" or Machine == "\x64\x86":
        outFileName += ".obj"
    elif Machine == "\x00\x00" and Extra == "\xFF\xFF": #Import Library
        outFileName += ".obj"
    else:
        outFileName += ".bin"
    print ">>> " + outFileName
    fOut = open(outFileName,"wb")
    fOut.write(cMem)
    fOut.close()
    c = c + 1


#----------------------------------------------------------------------------
print "Now reading first Linker Member"

NumLinkerMembers = len(LinkerMembers)

#Parse first Linker Member
#It is in Big-Endian
Offsets_First = []
Strings_First = []
if NumLinkerMembers >= 1:
    cLinkMem = Members[LinkerMembers[0]]
    if cLinkMem == "":
        print "First Linker Member is empty"
    else:
        lenMem = len(cLinkMem)
        ToBeReadSize = 4
        if ToBeReadSize >= lenMem:
            print "First Linker Member is too small"
        else:
            Runner = 0
            s_NumSymbols = (cLinkMem[Runner:Runner+4])[::-1]
            Runner += 4
            NumSymbols = struct.unpack("L",s_NumSymbols)[0]
            print "Number of Symbols: " + str(NumSymbols)
            SzSymbols = (NumSymbols * 4)
            ToBeReadSize += SzSymbols
            if ToBeReadSize >= lenMem:
                print "Boundary error while reading first Linker Member"
            else:
                Offsets = cLinkMem[Runner:Runner+SzSymbols]
                Runner += SzSymbols
                cOffset = 0
                while cOffset < SzSymbols:
                    sOffX = (Offsets[cOffset:cOffset+4])[::-1]
                    OffX = struct.unpack("L",sOffX)[0]
                    Offsets_First.append(OffX)
                    OStr = ""
                    OStr += str(hex(OffX))
                    OStr += ": "
                    StrX = GetNextString(cLinkMem,Runner,lenMem)
                    OStr += StrX
                    #print OStr
                    Strings_First.append(StrX)
                    Runner += (len(StrX)+1)
                    cOffset += 4

NumOffsets = len(Offsets_First)
NumStrings = len(Strings_First)
NumUniqueOffsets = GetNumberOfUniqueElements(Offsets_First)

NewOffsets_First = []
NewStrings_First = []

if NumOffsets == NumStrings:
    c = 0
    while c < NumOffsets:
        cOffsetXX = Offsets_First[c]
        Found = False
        for cc in range(0,len(NewOffsets_First)):
            cOffsetYY = NewOffsets_First[cc]
            if cOffsetYY == cOffsetXX:
                Found = True
                break
        if Found == False:
            NewOffsets_First.append(cOffsetXX)
            AllMemSymbols = ""
            for ccc in range(0,NumOffsets):
                xxOffxx = Offsets_First[ccc]
                if xxOffxx == cOffsetXX:
                    AllMemSymbols += Strings_First[ccc]
                    AllMemSymbols += "\x09"  #I will use Tab as String separator
            NewStrings_First.append(AllMemSymbols)
        c = c + 1

if NumUniqueOffsets != len(NewStrings_First):
    print "Error reading first member symbols"
else:
    for c in range(0,NumUniqueOffsets):
        Offset = NewOffsets_First[c]
        print str(hex(Offset)) + " ===> "
        AllSymbols = NewStrings_First[c]
        Symbols = AllSymbols.split("\x09")
        for Symbol in Symbols:
            if Symbol != "":
                print Symbol
#-------------------------------------------------------------------------
#Optional
#Parse second Linker Member 
#Second Linker Member represents a map of full .Lib File
#It is Little-Endian

print "Now parsing second Linker Member....."

MemberOffsets = []
Indices = []
Symbols = []
if NumLinkerMembers >= 2:
    cLinkMem_ = Members[LinkerMembers[1]]
    if cLinkMem_ == "":
        print "Second Linker Member is empty"
    else:
        lenMem_ = len(cLinkMem_)
        ToBeReadSize = 4
        if ToBeReadSize >= lenMem_:
            print "Second Linker Member is too small"
        else:
            Runner = 0
            s_NumMembers_ = cLinkMem_[Runner:Runner+4]
            NumMembers_ = struct.unpack("L",s_NumMembers_)[0]
            #NumMembers is number of Members not excluding Linker members (not sure about long names member)
            print "Number of Members: " + str(NumMembers_)
            Runner += 4
            ToBeReadSize += (NumMembers_*4)
            if ToBeReadSize >= lenMem_:
                print "Boundary error while reading second Linker Member"
            else:
                c = 0
                while c < NumMembers_:
                    MemberOffsets.append(struct.unpack("L",cLinkMem_[Runner:Runner+4])[0])
                    Runner += 4
                    c = c + 1
                ToBeReadSize += 4
                if ToBeReadSize >= lenMem_:
                    print "Boundary error while reading second Linker Member"
                else:
                    NumberOfSymbols_ = struct.unpack("L",cLinkMem_[Runner:Runner+4])[0]
                    print "Number of Symbols: " + str(NumberOfSymbols_)
                    Runner += 4
                    ToBeReadSize += (NumberOfSymbols_*2)
                    if ToBeReadSize >= lenMem_:
                        print "Boundary error while reading second Linker Member"
                    else:
                        IndicesX = cLinkMem_[Runner:Runner+(NumberOfSymbols_*2)]
                        for u in range(0,NumberOfSymbols_):
                            Indices.append(struct.unpack("H",IndicesX[u*2:u*2+2])[0])
                        Runner += (NumberOfSymbols_*2)
                        c = 0
                        while c < NumberOfSymbols_:
                            StrX = GetNextString(cLinkMem_,Runner,lenMem_)
                            #print StrX
                            Symbols.append(StrX)
                            Runner += (len(StrX)+1)
                            c = c + 1

NumMemberOffsets = len(MemberOffsets)
NumIndices = len(Indices)
NumSymbols = len(Symbols)

if NumSymbols != NumIndices:
    print "Error reading second member symbols"


NewOffsets_Second = []
NewStrings_Second = []


for i in range(0,NumMemberOffsets):
    cOffset = MemberOffsets[i]
    NewOffsets_Second.append(cOffset)
    ii = i + 1
    AllSymbols = ""
    for iii in range(0,NumIndices):
        Index = Indices[iii]
        if Index == ii:
            AllSymbols += Symbols[iii]
            AllSymbols += "\x09"

    NewStrings_Second.append(AllSymbols)
    

NumUniqueOffsets = len(NewOffsets_Second)
for i in range(0,NumUniqueOffsets):
    print str(hex(NewOffsets_Second[i])) + " ===> "
    AllSymbols = NewStrings_Second[i]
    Symbols = AllSymbols.split("\x09")
    for Symbol in Symbols:
        if Symbol != "":
            print Symbol


#Parse LongNames Member
print "Now printing all names in LongNames member"
if len(LongNamesMembers)>=1:
    lngMem = Members[LongNamesMembers[0]]
    len_lngMem = len(lngMem)
    Runner = 0
    while Runner < len_lngMem:
        StrX = GetNextString(lngMem,Runner,len_lngMem)
        print StrX
        Runner += (len(StrX)+1)
