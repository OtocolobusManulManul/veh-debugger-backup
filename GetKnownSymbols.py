from idautils import *
from idaapi import *
from idc import *
import ida_bytes
import pathlib
import os
import sys

print("\n\n")
print("parsing global vars")
print("="*70)

filepath = get_input_file_path()[::-1]
baseModName = filepath[0:filepath.index("\\")][::-1].lower()[0:-4]

addresses = []
names = []

for name in Names():
  addresses += [name[0]]
  names += [name[1]]

def is_user_name(ea):
  f = ida_bytes.get_full_flags(ea)
  return hasUserName(f)


segments = {}

for segment in Segments():
    segments = dict(segments, **{idc.get_segm_name(segment) : {"start" : idc.get_segm_start(segment), "end" : idc.get_segm_end(segment)}})

text = segments['.text']['start']
pdata = segments['.pdata']['start']
pdataEnd = segments['.pdata']['end']
data = segments['.data']['start']

knownFunctionDatabase = ""
knownGlobalVarDatabase = ""

n = 0
data_range = range(segments['.data']['start'], segments['.data']['end'] + 1) 
#data2_range = range(segments['.data_2']['start'], segments['.data_2']['end'] + 1)

while n < len(addresses):
  
  #print(addresses[n])
  
  if addresses[n] in data_range: #or addresses[n] in data2_range:
    
    addr = addresses[n]
    name = names[n]
    
    if is_user_name(addr):
      generated_name = name[0] == "?" or name[0] == "_"
      if len(name) > 3: generated_name = generated_name or name[0:3] == "jpt" or name[0:3] == "def" or name[0:3] == "sub"
      if len(name) > len(baseModName): generated_name = generated_name or name[0:len(baseModName)] == baseModName
      
      if not generated_name: print(hex(addresses[n]), names[n])
  
  n += 1

print("\n\nparsing for known functions")
print("="*70)

rva = 1
exceptionDir_index = pdata

while rva != 0:

  rva = int.from_bytes(get_bytes(exceptionDir_index, 4), "little")
  funcea = text + (rva - 0x1000)
  
  if funcea in addresses:
    name = names[addresses.index(funcea)]
  
  else:
    exceptionDir_index += (12)  
    continue 

  #better than putting it on one line
  generated_name = name[0] == "?" or name[0] == "_"
  if len(name) > 3: generated_name = generated_name or name[0:3] == "jpt" or name[0:3] == "def" or name[0:3] == "sub"
  if len(name) > len(baseModName): generated_name = generated_name or name[0:len(baseModName)] == baseModName

  if not generated_name and is_user_name(funcea):
    print(hex(funcea), "\t", hex(rva), "\t", name)
    knownFunctionDatabase += str(hex(rva)) + "\t" + name + "\n"
  
  n += 1
  exceptionDir_index += (12)

fname = "knownSymbols"
libBackupName = "knownSymbols-ody" #YOU MUST SET THIS MANUALLY
                                   #IDA won't let you use STDin
                                   #in a script

localfile = open(os.getcwd() + "\\" + fname + ".dat", "w")
libcopy = open(str(pathlib.Path(__file__).parent.resolve()) +  "\\" + libBackupName + ".dat", "w")

localfile.write(knownFunctionDatabase)
libcopy.write(knownFunctionDatabase)

localfile.close()
libcopy.close()