'''
execute this first to get all exes in list:
find /home/user/Desktop/cb-multios-master/build/challenges/ -type f ! -name "*.*" -perm /u=x,g=x,o=x -printf "%p\n" > cb_multios_exes_paths.txt

then use this file to copy all of the exes to a new location
'''

import shutil, os
import csv

files = list(open('cb_multios_exes_paths.txt','r').read().splitlines())

#os.mkdir('cb_multios_binaries_originalvpatched')

for f in files:
    shutil.copy(f, 'cb_multios_binaries_originalvpatched')
