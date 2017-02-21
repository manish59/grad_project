def remove_white_space(string):
    new_string = ""
    for i in string:
        if i == " ":
            continue
        else:
            new_string = new_string + i
    return new_string
class _dlls:
	dict_of_locations={}
	def __init__(self,file_name):
		self.file_name=file_name
		buffer=open(self.file_name)
		temp_buffer=buffer.readlines()
		for i in range(len(temp_buffer)):
			if temp_buffer[i][0]=="*":
				index=temp_buffer[i+1].find("pid")
				name=temp_buffer[i+1][:index]
				pid=temp_buffer[i+1][index+7:index+11]
				location=temp_buffer[i+2][15:]
				self.dict_of_locations.setdefault(remove_white_space(pid),[]).append(remove_white_space(name))
				self.dict_of_locations.setdefault(remove_white_space(pid), []).append(remove_white_space(location))
if __name__=="__main__":
        a=_dlls("dlllist")