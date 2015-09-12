import os,sys,time,datetime,struct


def StrReverse(Str):
    return Str[::-1]

def GetNextString(Str,Offset):
    if Str == "":
        return ""
    NewStr = ""
    i = Offset
    while Str[i] != "\x00":
        NewStr += Str[i]
        i = i + 1
    return NewStr
    
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
    if Machine == "\x4C\x01" or Machine == "\x64\x86":
        outFileName += ".obj"
    else:
        outFileName += ".bin"
    print ">>> " + outFileName
    fOut = open(outFileName,"wb")
    fOut.write(cMem)
    fOut.close()
    c = c + 1

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
        if lenMem < 4:
            print "First Linker Member is too small"
        else:
            s_NumSymbols = (cLinkMem[0:4])[::-1]
            NumSymbols = struct.unpack("L",s_NumSymbols)[0]
            print "Number of Symbols: " + str(NumSymbols)
            sz_of_offsets = NumSymbols * 4
            offStrings = 4 + sz_of_offsets
            if 4 + (sz_of_offsets) >= lenMem:
                print "Boundary error while reading first Linker Member"
            else:
                Offsets = cLinkMem[4:4+sz_of_offsets]
                cOffset = 0
                while cOffset < sz_of_offsets:
                    sOffX = (Offsets[cOffset:cOffset+4])[::-1]
                    OffX = struct.unpack("L",sOffX)[0]
                    Offsets_First.append(OffX)
                    print hex(OffX)
                    StrX = GetNextString(cLinkMem,offStrings)
                    print StrX
                    offStrings += (len(StrX)+1)
                    cOffset += 4
            
#Optional
#Parse second Linker Member 
#Second Linker Member represents a map of full .Lib File
#It is Little-Endian

print "Now parsing second Linker Member....."

OffMemberHeaders = []
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
                    OffMemberHeaders.append(struct.unpack("L",cLinkMem_[Runner:Runner+4])[0])
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
                        Indices = cLinkMem_[Runner:Runner+(NumberOfSymbols_*2)]
                        Runner += (NumberOfSymbols_*2)
                        c = 0
                        while c < NumberOfSymbols_:
                            StrX = GetNextString(cLinkMem_,Runner)
                            print StrX
                            Symbols.append(StrX)
                            Runner += (len(StrX)+1)
                            c = c + 1

#Parse LongNames Member
if len(LongNamesMembers)>=1:
    lngMem = Members[LongNamesMembers[0]]
    len_lngMem = len(lngMem)
    Runner = 0
    while Runner < len_lngMem:
        StrX = GetNextString(lngMem,Runner)
        print StrX
        Runner += (len(StrX)+1)
