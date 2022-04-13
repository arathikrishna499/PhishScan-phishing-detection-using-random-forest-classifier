# importing the required modules
import os
import time

# main function
def main():
    

    # specify the path
    file_path = 'URL file.csv'

    # specify the days
    days = 14

    # converting days to seconds
    # time.time() returns current time in seconds
    seconds = time.time() - (days * 24 * 60 * 60)

    # checking whether the file is present in path or not
    if os.path.exists(file_path):

        # comparing with the days
        if seconds >= get_file_or_folder_age(file_path):

            # invoking the remove_file function
            remove_file(file_path)

        else:
            
            return 0

    else:
    
        # file/folder is not found
        print(f'"{file_path}" is not found')       



def remove_file(path):
    
	# removing the file
	if not os.remove(path):

		# success message
		print(f"{path} is removed successfully")

	else:

		# failure message
		print(f"Unable to delete {path}") 


def get_file_or_folder_age(path):
    
	# getting ctime of the file/folder
	# time will be in seconds
	ctime = os.stat(path).st_ctime

	# returning the time
	return ctime

