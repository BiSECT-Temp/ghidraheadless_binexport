'''
1. read file of cb_multios_execs
2. create dictionary k (original), v (patched)
3. cmd: bindiff orig.BinExport patched.BinExport
4. analysis (to get diff function names)
'''

import sqlite3
import pandas as pd
import glob
import subprocess, os

files = sorted([file for file in glob.glob('/home/user/Desktop/cbmultios_BinExports/*.BinExport')])
#files = list(open('cb_multios_execs.txt','r').read().splitlines())

def make_pairs(files):
    originals = [file for file in files if "_patched" not in file]
    patched = [(file.replace('.BinExport', '_patched.BinExport')) for file in originals]
    pairs = dict(zip(originals, patched))
    #pairs = dict(zip(files[::2], files[1::2]))
    return pairs

def make_bindiff(original, patched):
    output_dir = '/home/user/Desktop/cbmultios_BinExports/bindiffs/'
    full_path = output_dir + original.split('/')[-1].replace('.BinExport','') + '_vs_' + patched.split('/')[-1].replace('.BinExport','') + '.BinDiff'
    cmd = ['/usr/bin/bindiff', original, patched, '--output_dir='+ output_dir]
    subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return full_path

def bindiff_to_csv(bindiff_diff):
    print('bindiff to csv: ', bindiff_diff)
    #bindiff_diff = bindiff_diff.replace('.BinExport','')
    db = sqlite3.connect(bindiff_diff)
    cursor = db.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    try:
        fun_table = tables[4]
        #table = pd.read_sql_query("SELECT * from %s" % fun_table, db)
        table = pd.read_sql_query("SELECT * from %s" % fun_table, db)

        output_dir = '/home/user/Desktop/cbmultios_BinExports/bindiffs/funtables/'
        name = output_dir + bindiff_diff.split('/')[-1] + '_funtable.csv'
        table.to_csv(name, index_label='index')
        cursor.close()
        db.close()
        return name

    except:
        return 'error'

def get_fcn(name_sample_addr):
    try:
        index = fun_df.index[fun_df['sample_name_addr'] == name_sample_addr].tolist()[0]
        fun_name = fun_df.iloc[index]['fun_name']
    except:
        fun_name='not_found'
    return fun_name

def coorelate_fun_names(table_path):
    bindiff_df = pd.read_csv(table_path, index_col=[0])
    #index,id,address1,address2,similarity,confidence,flags,algorithm,evaluate,commentsported,basicblocks,edges,instructions
    bindiff_df['original_sample'] = str(table_path.split('/')[-1].replace('_funtable.csv','')).split('_vs_')[0]

    bindiff_df['patched_sample'] = str(table_path.split('/')[-1].replace('_funtable.csv','')).split('_vs_')[1]

    bindiff_df['original_sample_addr'] = bindiff_df['original_sample'] + '_' + str(bindiff_df['address1'])

    bindiff_df['patched_sample_addr'] = bindiff_df['patched_sample'] + '_' + str(bindiff_df['address2'])

    bindiff_df['orig_fun_name'] = bindiff_df['original_sample_addr'].apply(lambda x: get_fcn(x))
    bindiff_df['patched_fun_name'] = bindiff_df['patched_sample_addr'].apply(lambda x: get_fcn(x))

    csv_name = base_dir + table_path.split('/')[-1].replace('.BinDiff','') + '_finaldf.csv'
    bindiff_df.to_csv(csv_name)
    return bindiff_df

base_dir = '/home/user/Desktop/cbmultios_BinExports/resources/'
fun_df = pd.read_csv(base_dir+'sample_functions.csv')
fun_df.columns = ['path', 'fun_name', 'addr']
fun_df['name'] = fun_df['path'].apply(lambda x: x.split('/')[-1])
fun_df['sample_name_addr'] = fun_df['name'] + '_' + fun_df['addr']

pairs = make_pairs(files)
bindiffs = [make_bindiff(k, v) for k, v in pairs.items()]
bindiff_fcn_paths = [bindiff_to_csv(bindiff) for bindiff in bindiffs]
final_dfs = [coorelate_fun_names(bindiff_fcn_path) for bindiff_fcn_path in bindiff_fcn_paths if bindiff_fcn_path != 'error']
final_combined = pd.concat(final_dfs, axis=0)
final_combined.to_csv('/home/user/Desktop/cbmultios_BinExports/resources/final_combined.csv')
