'''
date created: 12 April 2021
notes: this script will extract function information and create a bindiff from a binary using ghidra, 
the output is a .csv with address information for each function, and the *.bindiff format

process:
1. sample_functions_cpy.py (get binExport and function info using ghidra headless)
2. auto_bindiff.py (to get the bindiffs for each pair)
3. bindiff_fcn_correlation.py (find different functions, and coorelate function names to bindiff output using addrs)
'''

import csv
from ghidra.app.script import GhidraScript
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.util.exporter import Exporter
from com.google.security.binexport import BinExportExporter
from java.io import File

function_list = []
program_name = currentProgram.getName()
path = currentProgram.getExecutablePath()
listing = currentProgram.getListing()
func_manager = currentProgram.getFunctionManager()
internal_fcn_objs = func_manager.getFunctions(True)


addr_set = currentProgram.getMemory()
f = File(program_name + '.BinExport')
exporter = BinExportExporter() #Binary BinExport (v2) for BinDiff
exporter.export(f, currentProgram, addr_set, monitor)


for fun_obj in internal_fcn_objs:
    fun_name = fun_obj.getName()
    min_addr = fun_obj.getBody().getMinAddress().getOffset()
    function_list.append([path, fun_name, min_addr])

with open('/home/user/Desktop/cbmultios_BinExports/ghidra_function_data/sample_functions_addresses.csv', 'a') as f:
    writer = csv.writer(f)
    writer.writerows(function_list)
