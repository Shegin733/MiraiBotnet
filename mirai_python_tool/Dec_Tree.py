# Decisoion Tree Classification # Classification template
import pickle

# Importing the libraries
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn import datasets
from sklearn.metrics import confusion_matrix
# Importing the dataset
dataset = pd.read_csv(r'C:\Users\Shegin\Desktop\MiraiFoe\data.csv')
X = dataset.iloc[:, [3,6,9,10,13]].values
y = dataset.iloc[:, 12].values

# Splitting the dataset into the Training set and Test set
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.25, random_state = 0)
from sklearn.tree import DecisionTreeClassifier
classifier = DecisionTreeClassifier(criterion = 'entropy', random_state =0)
classifier.fit(X_train,y_train )

# Predicting the Test set results
y_pred = classifier.predict(X_test)

from sklearn.metrics import accuracy_score

# Calculate accuracy
accuracy = accuracy_score(y_test, y_pred)

# Print accuracy
print(f'Accuracy: {accuracy:.2f}')

cm = confusion_matrix(y_test, y_pred)
print("Confusion Matrix:")
print(cm)
def ip_to_numeric(ip_address):
    # Convert the IP address from string to a numerical representation
    # Split the IP address by '.' and convert each part to an integer
    ip_parts = ip_address.split('.')
    numeric_ip = sum(int(part) * (256 ** index) for index, part in enumerate(reversed(ip_parts)))
    return numeric_ip

def predict_threat(source_ip, source_port, target_ip, target_port):
    # Convert IP addresses to numerical format
    source_ip_num = ip_to_numeric(source_ip)
    target_ip_num = ip_to_numeric(target_ip)
    
    # Extract the host address from the last part of the target IP address
    host_address = int(target_ip.split('.')[-1])
    
    # Create the feature vector
    features = np.array([[source_ip_num, source_port, target_ip_num, target_port, host_address]])
    
    # Use the trained classifier to predict
    y_pred = classifier.predict(features)
    
    # Assuming the classifier's prediction includes the required outputs
    # (you may need to adjust the following code based on your classifier's actual output)
    threat_confidence = "Confidence: Placeholder"  # Placeholder, replace with actual calculation if available
    threat_classify = "Threat Classification: Placeholder"  # Placeholder, replace with actual calculation if available
    prediction = y_pred[0]  # The classifier's predicted class
    
    # Return a dictionary with the predictions
    return {
        
        "Prediction": prediction
    }

# Example usage of the function:
result = predict_threat("10.16.0.5", 54650 , "10.16.0.100",  23)
print(result)

# File path for the pickle file
pickle_file_path = 'classifier.pkl'

# Save the trained classifier to the pickle file
with open(pickle_file_path, 'wb') as file:
    pickle.dump(classifier, file)

print(f"The classifier has been saved to {pickle_file_path}")
