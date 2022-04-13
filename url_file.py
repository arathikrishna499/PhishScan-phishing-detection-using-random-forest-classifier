import csv
import time
import os

#To search data in file
def url_search(url):

    start_time=time.time()
    s=[]
    flag='True'

    with open('URL file.csv','a',newline='') as f , open('URL file.csv','r') as csvfile:
        
        file_path = 'URL file.csv'
        # check if size of file is 0
        if os.path.getsize(file_path) == 0:

            header = ['URL', 'STATUS','FEATURE SET']
            writeCSV = csv.writer(f,delimiter=',')
            writeCSV.writerow(header)
            flag='False'
            
        else:  

            readCSV = csv.reader(csvfile,delimiter=',')
            for row in readCSV:
                if row:
                    if (url==row[0]):
                        flag='True'
                        s.append(row[1])
                        s.append(row[2])
                        break
                    else:
                        flag='False'
        f.close()
        csvfile.close()

    end_time=time.time()
    s.append(end_time-start_time)

    if flag=='True':
        return s
    else:   
        return 'NOT FOUND'

#To write data to file
def url_update(url,result,list):
       
    data = []
    data.append(url)
    data.append(result)
    data.append(list)
   
    with open('URL file.csv','a',newline='') as csvfile:
                
        writeCSV = csv.writer(csvfile,delimiter=',')
        writeCSV.writerow(data)
        csvfile.close()
        