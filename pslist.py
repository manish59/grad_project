import collections
import os
import subprocess
def remove_white_space(string):
    new_string = ""
    for i in string:
        if i == " ":
            continue
        else:
            new_string = new_string + i
    return new_string
class record(object):
    def __init__(self,m_address,name,pid,ppid,threads,hands,session,wow64,start,last):
		self.m_address=m_address
		self.name=name
		self.pid=pid
		self.ppid=ppid
		self.threads=threads
		self.hands=hands
		self.session=session
		self.wow64=wow64
		self.start=start
		self.last=last
class process(record):
	critical_process=["System","smss.exe","csrss.exe","winlogon.exe","services.exe","lsass.exe","wininit.exe","logonui.exe","svchost.exe","RPCSS","svchost.exe"]
	list_of_process=[]
	comments=[]
	def __init__(self,file_name):
        	self.file_name=file_name
		buffer=open(self.file_name) #how to append multiple values to a dict in python
        	temp_list=buffer.readlines()
        #print temp_list
       		self.dict_of_process = collections.defaultdict(list)
        	for items in temp_list[2:]:
            		address=remove_white_space(items[0:10])
           		name=remove_white_space(items[11:31])
            		pid=remove_white_space(items[32:38])
            		ppid=remove_white_space(items[39:45])
            		threads=remove_white_space(items[46:52])
            		handles=remove_white_space(items[54:62])
            		session=remove_white_space(items[63:69])
            		wow64=remove_white_space(items[70:76])
            		start=remove_white_space(items[76:107])
            		end=remove_white_space(items[107:138])
		        a=record(address,name,pid,ppid,threads,handles,session,wow64,start,end)
		        self.list_of_process.append(a)
	def display(self): #Displays the list of processses running
		for i in self.list_of_process:
			print i.name
class artifacts(process):
	count=0 # stores frequencey of processes
	list_of_suspects=[]
	comments=[]
	def artifact(self):
                services_obj=[x for x in self.list_of_process if x.name=="services.exe"]
		services=services_obj[0].pid
		wininit_obj=[x for x in self.list_of_process if x.name=="wininit.exe" or x.name=="winlogon.exe"]
		wininit=wininit_obj[0].pid
		spoolsv_obj=[x for x in self.list_of_process if x.name=="spoolsv.exe"]
		spoolsv=spoolsv_obj[0].ppid
		searchindexer_obj=[x for x in self.list_of_process if x.name=="SearchIndexer.exe"]
		if spoolsv!=services:
			#print "spoolsv.exe is not having services.exe as parent"
			self.list_of_suspects.append(spoolsv_obj)
			self.comments.append("spoolsv.exe is not having services.exe as parent")
                flag=0
		l_flag=0
		programs=[]
                for i in self.list_of_process:
			programs.append(i.name) #appending all the programs to the programs list
                for i in self.list_of_process: #checking the parent child relations ship
                        if i.name=="svchost.exe":
                                if i.ppid==services:
                                        flag=flag+2
				else:
					flag=flag+1
	                	if flag%2!=0:
        	                	#print "SVChost with pids "+str(i.pid)+" are not following services.exe"
					self.list_of_suspects.append(i)
					self.comments.append("SVChost with pids are not following services.exe")
			if i.name=="lsass.exe":
				if i.ppid==wininit:
					l_flag=l_flag+2
				else:
					l_flag=l_flag+1
				if l_flag%2!=0:
					#print "LSASS is not having the parent as wininit or winlogon whose pid is "+ str(i.pid)
					self.list_of_suspects.append(i)
					self.comments.append("LSASS is not having the parent as wininit or winlogon")				
		#if l_flag%2==0:
			#print "LSASS is having parent wininit or winlogon"
		#if flag%2==0:
			#print "SVCHOST.exe is having parent as services"  
		counter=collections.Counter(programs)
		if counter["services.exe"]!=1:
			#print "Servies.exe not occured only once"
			for i in services:#appending all the occured services.exe objects
				self.list_of_suspects.append(i)
				self.comments.append("Services are not occuring once")
		if counter["csrss.exe"]!=1:
			#print "csrss.exe is not occured only once"
			csrss=[x for x in self.list_of_process if x.name=="csrss.exe"]
			for i in csrss:
				self.list_of_suspects.append(i)
				self.comments.append("CSRSS are not occuring once")
		if counter["lsass.exe"]!=1:
			#print "lsass.exe is not occured only once"
			lsass=[x for x in self.list_of_process if x.name=="lsass.exe"]
			for i in lsass:
				self.list_of_suspects.append(i)
				self.comments.append("LSASS are not occuring once")
		diff=list(set(programs)-set(self.critical_process))
		#print "Critical process -normal programs: \n",diff
		x=[i for i in self.list_of_process if i.name[-4:]!=".exe" and i.name!="System"]
		#print "Some Miscallenous process are \n",x
		for i in x:		
			self.list_of_suspects.append(i)
			self.comments.append("Slightly doubtful")
if __name__=='__main__':
	sample=raw_input("Enter your sample for verifying :")
	command="volatility pslist -f "+sample+">>pslist"
	command2="volatility psscan -f "+sample+">>psscan"
	a=subprocess.call(command,shell=True)
	a1=subprocess.call(command2,shell=True)
	hai=artifacts("pslist")
	hai.artifact()

