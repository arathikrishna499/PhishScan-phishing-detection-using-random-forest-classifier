import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

   
data=pd.read_csv('uci dataset.csv')
data=data.drop('id',1)

y=data['Result']
x=data.drop('Result',axis=1)
    
#print(x.shape)
#print(x.isnull().sum())

x_train, x_test, y_train, y_test=train_test_split(x,y,test_size=0.25,random_state=42,stratify=y)


rfc=RandomForestClassifier(random_state=42)
rfc=rfc.fit(x_train, y_train)

score=rfc.score(x_test , y_test)
#print("Score = ",score)
print("Accuracy score = ",score*100)

pickle.dump(rfc, open('rfc_model','wb'))
