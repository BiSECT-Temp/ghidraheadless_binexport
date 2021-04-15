'''
author: kayla n. afanador
date created: 12 April 2021
notes: this script will extract function information and create a bindiff from a binary using ghidra, the output is a .csv with address information for each function, and the *.bindiff format

process:
1. sample_functions_cpy.py (get binExport and function info using ghidra headless)
2. auto_bindiff.py (to get the bindiffs for each pair)
3. bindiff_fcn_correlation.py (find different functions, and coorelate function names to bindiff output using addrs)

ghidra headless(ubuntu guest):
/home/user/.local/java_applications/ghidra_9.1.2_PUBLIC/support/analyzeHeadless /home/user/Desktop/ TestProject -import /home/user/Desktop/cb_multios_binaries_originalvpatched/ -deleteProject -analysisTimeoutPerFile 100 -scriptPath /home/user/Desktop/ -postScript /home/user/Desktop/sample_functions_cpy.py -scriptlog /home/user/Desktop/log.log

ghidra headless(host):
/Users/kaylakeen/Desktop/GHIDRA/support/analyzeHeadless /Volumes/Research/VulnerabilityDatasets/Vulnerability_datasets/code/patch_diffs TestProject -import /Volumes/Research/VulnerabilityDatasets/Vulnerability_datasets/cb-multios-master_executables/ -deleteProject -scriptPath /Volumes/Research/VulnerabilityDatasets/Vulnerability_datasets/code/patch_diffs/sample_functions.py -postScript /Volumes/Research/VulnerabilityDatasets/Vulnerability_datasets/code/patch_diffs/sample_functions.py -scriptlog /Volumes/Research/VulnerabilityDatasets/Vulnerability_datasets/code/patch_diffs/log.log

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

'''
addr_set = currentProgram.getMemory()
f = File(program_name + '.BinExport')
exporter = BinExportExporter() #Binary BinExport (v2) for BinDiff
exporter.export(f, currentProgram, addr_set, monitor)
'''

for fun_obj in internal_fcn_objs:
    fun_name = fun_obj.getName()
    #entry_point = fun_obj.getEntryPoint()
    min_addr = fun_obj.getBody().getMinAddress().getOffset()
    #last_addr = fun_obj.getBody().getMaxAddress().getOffset()
    #num_refs = len(currentProgram.referenceManager.getReferencesTo(toAddr(fun_name)))
    function_list.append([path, fun_name, min_addr])

with open('/home/user/Desktop/cbmultios_BinExports/ghidra_function_data/sample_functions_addresses.csv', 'a') as f:
    writer = csv.writer(f)
    writer.writerows(function_list)
