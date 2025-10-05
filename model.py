import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.feature_selection import mutual_info_classif

pd.set_option('display.max_columns', None)
plt.rcParams['figure.figsize'] = (12,6)

data = pd.read_csv('phishing_dataset.csv')

data.rename(columns={'CLASS_LABEL': 'labels'}, inplace=True)
X = data.drop(['id', 'labels'], axis=1)
y = data['labels']

discrete_features = X.dtypes == int

mi_scores = mutual_info_classif(X, y, discrete_features=discrete_features)
mi_scores = pd.Series(mi_scores, name='MI Scores', index=X.columns)
mi_scores = mi_scores.sort_values(ascending=False)
# print (mi_scores)


float_cols = data.select_dtypes('float64').columns
for c in float_cols:
    data[c] = data[c].astype('float32')

int_cols = data.select_dtypes('int64').columns
for c in int_cols:
    data[c] = data[c].astype('int32')

# data.info()

# print (data.columns[:25])


def train_model(data, top_n):
    top_n_features = mi_scores.sort_values(ascending=False).head(top_n).index.tolist()
    print (top_n_features)
    # top_n_features = data.columns[:top_n]
    X=data[top_n_features]#.drop(['id'],axis=1)
    y=data['labels']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, shuffle=True)

    model = RandomForestClassifier(
            n_estimators=200,      # number of trees
            max_depth=None,       # let trees grow fully
            random_state=42,
            class_weight="balanced"  # handle imbalance if present
        )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    accuracy = accuracy_score(y_test, y_pred)

    print("Precision:", precision, "Recall:", recall, "F1:", f1, "Accuracy:", accuracy)

    return model,top_n_features

model, top_n_features = train_model(data, top_n=32)
joblib.dump(model, 'phishing_model.pkl')
joblib.dump(top_n_features,'feature_columns.pkl')
