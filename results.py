from pslist import artifacts
from psscan import  pool
from totaldll import _dlls
from psxview import _psxview
import subprocess
comments=[]
if __name__=="__main__":
	sample=raw_input("Enter your sample for verifying :")
	command="volatility pslist -f "+sample+">pslist"
	command2="volatility psscan -f "+sample+">psscan"
	a=subprocess.call(command,shell=True)
	a1=subprocess.call(command2,shell=True)
	pslist_obj=artifacts("pslist") # instatiing the pslist from here
	pslist_obj.artifact()
    #pslist_obj.artifact.list_of_suspects stores the list of suspected processes
	psscan_obj=pool("psscan")
	list_of_poolspid=psscan_obj.dict_of_pool.keys()  #dictionary with pools of keys
        _dlls_obj=_dlls("dlllist")
    # _dlls_obj.dict_of_locations is the dictionary which stores the locations of all the running process
	_psxview_obj=_psxview("psxview") #instanting the psxview with the object
        print _psxview_obj.dict_of_results.keys()
