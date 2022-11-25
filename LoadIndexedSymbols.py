from idautils import *
from idaapi import *
from idc import *
import ida_bytes
import pathlib
import os
import sys


SYMBOL_FILE = "knownSymbols-ody"     #no I/O in ida interpreter
                                     #so you gotta set it up here

filePath = str(pathlib.Path(__file__).parent.resolve()) +  "\\" + SYMBOL_FILE + ".dat"

print(filePath)

symboldb = open(str(pathlib.Path(__file__).parent.resolve()) +  "\\" + SYMBOL_FILE + ".dat")

symboldb = symboldb.read()

symbols = []

while (bool(len(symboldb))):
    
    SymbolIndex = [None, None]

    index = 0
    newIndex = symboldb.index("\t")
    
    SymbolIndex[0] = symboldb[index:newIndex]
    index = newIndex
    newIndex = symboldb.index("\n")
    SymbolIndex[1] = symboldb[index + 1:newIndex]
    symboldb = symboldb[newIndex + 1:]
    symbols += [SymbolIndex]

print (symbols)

segments = {}

for segment in Segments():
    segments = dict(segments, **{idc.get_segm_name(segment) : {"start" : idc.get_segm_start(segment), "end" : idc.get_segm_end(segment)}})

text = segments['.text']['start']

for symbol in symbols:
    
    funcea = int(symbol[0][2:], 16) + text - 0x1000
    print("address of function,", symbol[1] , ":", hex(funcea))
    set_name(funcea, symbol[1], SN_FORCE)

print("\n\DONE\n")
