# ghidraheadless_binexport

The following is a no frills Python script to support using Ghidra headless (i.e., the API)  with BinExport. 

## Prerequisites: 
- Python
- BinExport, found [here](https://github.com/google/binexport/tree/main/java/BinExport)
- Ghidra, found [here]()

## Details: 
BinExport is the exporter component of BinDiff. Follow the link above to ensure BinExport is integrated with your current installation of Ghidra.
Ghidra, is a prominent open source reversing suite. BinExport can be integrated into Ghidra as a plugin, and allows users to easily identify similar and differing functions in disassembled code. You can read more about the BinDiff diffing algorithm [here](https://www.zynamics.com/bindiff/manual/index.html#chapUnderstanding). 


While the GUI version of BinExport is well documented, there is little information available on using BinDiff with the Ghidra API.

### How it works...

#### Creating BinExports and extracting function information using Ghidra headless
Ultimately, the user should run the script via Ghidra Headless like so, 

```python
/home/user/.local/java_applications/ghidra_9.1.2_PUBLIC/support/analyzeHeadless /home/user/Desktop/ TestProject -import /home/user/Desktop/bath_to_binaries/ -deleteProject -analysisTimeoutPerFile 100 -scriptPath /home/user/Desktop/ -postScript /home/user/Desktop/sample_functions_cpy.py -scriptlog /home/user/Desktop/log.log
```

Note: path information should be modified as appropriate.

In the ```auto_bindiff.py``` script, this line, 
```python
exporter.export(f, currentProgram, addr_set, monitor)
```
is used to export a ```sample_name.BinExport``` file for each sample analyzed, where ```sample_name``` is the name of the sample. 
These files will be used to create the ```BinDiff``` between ```n``` samples (an example of this is provided in the Jupyter notebook ```binexport_automation.ipynb```).

The following will output the ```fun_name``` and corresponding ```min_addr``` of each function in each sample to a .csv (the user can modify where this csv is placed, as desired)
```python
for fun_obj in internal_fcn_objs:
    fun_name = fun_obj.getName() # get the name of this function
    min_addr = fun_obj.getBody().getMinAddress().getOffset()
    function_list.append([path, fun_name, min_addr])
```

This information will then be correlated with the BinDiff output. 

#### Creating and Correlating BinDiff output
The Jupyter notebook ```binexport_automation.ipynb``` can be used to create BinDiffs for any two ```*.BinExport``` files created during the previous step.  

Specifically, the ```make_bindiff(original, patched)``` is used for this purpose. 

In the example provided in the notebook, we are examining functions in ```original``` and ```patched``` binaries, which have been provided as a dictionary.

```python
def make_bindiff(original, patched):
    bin_diff_path = '/usr/bin/bindiff'
    output_dir = '/home/user/Desktop/cbmultios_BinExports/bindiffs/'
    full_path = output_dir + original.split('/')[-1].replace('.BinExport','') + '_vs_' + patched.split('/')[-1].replace('.BinExport','') + '.BinDiff'
    cmd = [bin_diff_path, original, patched, '--output_dir='+ output_dir]
    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return full_path

bindiffs = [make_bindiff(k, v) for k, v in pairs.items()]
```

Then, ```bindiff_to_csv(bindiff_diff)``` is used to grab the ```function``` sqlite3 table from the ```BinDiff``` file. 

```python
def bindiff_to_csv(bindiff_diff):
    db = sqlite3.connect(bindiff_diff)
    cursor = db.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    try:
        fun_table = tables[4]
        table = pd.read_sql_query("SELECT * from %s" % fun_table, db)
        output_dir = '/home/user/Desktop/cbmultios_BinExports/bindiffs/funtables/'
        name = output_dir + bindiff_diff.split('/')[-1] + '_funtable.csv'
        table.to_csv(name, index_label='index')
        cursor.close()
        db.close()
        return name
    except:
        return 'error'
```

Finally, we simply use Pandas and Glob to read back in the data and correlate the function names for each sample using the ```sample name```
and ```min_addr``` information we collected during the Ghidra headless step. In our example, we ended up with a table that we could query for functions with less than pefect similarity. 
This allowed us to quickly identify functions modified during a patch, regardless of the initial source language. 
e.g., 
```python
final_combined.query('similarity < 1.0')
```


## Author Information
Kayla Afanador, knkeen@nps.edu
