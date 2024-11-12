import streamlit as st
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Load dataset and preprocess data
def load_and_preprocess_data(file):
    try:
        df = pd.read_csv(file)
        if df.empty:
            st.error("The uploaded CSV file is empty. Please upload a valid file.")
            return None, None, None, None

        df['Attack_Type'] = 0  # Initialize a label column

        # Label anomalies for each attack type
        df.loc[df['Info'].str.contains('DDOS', case=False, na=False), 'Attack_Type'] = 1
        df.loc[df['Info'].str.contains('MITM|Dup ACK|Spurious Retransmission|unseen segment', case=False, na=False), 'Attack_Type'] = 2
        df.loc[df['Info'].str.contains('SYN|FIN|NULL|XMAS|Echo', case=False, na=False), 'Attack_Type'] = 3

        # Feature selection - modify based on your dataset columns
        X = df[['Time', 'Length']]  # Example features
        y = df['Attack_Type']

        return train_test_split(X, y, test_size=0.3, random_state=42)

    except pd.errors.EmptyDataError:
        st.error("No columns to parse from file. Please upload a valid CSV file.")
        return None, None, None, None


# Function to train and evaluate models
def evaluate_models(X_train, X_test, y_train, y_test):
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000),
        "Decision Tree": DecisionTreeClassifier(),
        "Random Forest": RandomForestClassifier(),
        "SVM": SVC()
    }

    results = []
    for model_name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        
        # Compute evaluation metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        
        # Store results
        results.append({
            "Model": model_name,
            "Accuracy": accuracy,
            "Precision": precision,
            "Recall": recall,
            "F1 Score": f1
        })
    
    return pd.DataFrame(results)

# Main app function
def main():
    st.title("Anomaly Detection with Model Comparison")

    # File upload
    csv_file = st.file_uploader("Upload CSV File", type=["csv"])

    if csv_file is not None:
        st.write("### Uploaded File:")
        df = pd.read_csv(csv_file)
        st.write(df.head())

        # Load and preprocess data
        X_train, X_test, y_train, y_test = load_and_preprocess_data(csv_file)
        
        # Check if data is loaded successfully
        if X_train is None or X_test is None or y_train is None or y_test is None:
            return

        # Train and evaluate models for each attack type
        st.write("## Model Comparison for Anomaly Detection")
        
        # Run evaluation and get results table
        results_df = evaluate_models(X_train, X_test, y_train, y_test)
        
        # Display the results in a table
        st.write("### Model Performance Comparison")
        st.table(results_df)

        # Highlight best model for each metric
        st.write("### Best Models for Each Metric")
        st.write("Best Accuracy:", results_df.loc[results_df['Accuracy'].idxmax()])
        st.write("Best Precision:", results_df.loc[results_df['Precision'].idxmax()])
        st.write("Best Recall:", results_df.loc[results_df['Recall'].idxmax()])
        st.write("Best F1 Score:", results_df.loc[results_df['F1 Score'].idxmax()])

        # Explanation section
        st.write("## Explanation of Model Selection")
        st.info("This table shows the accuracy, precision, recall, and F1 score of each model for anomaly detection. These metrics help us determine which model performs best for each attack type (DDOS, MITM, Nmap).")

    
if __name__ == '__main__':
    main()
