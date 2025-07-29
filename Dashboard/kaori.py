import streamlit as st
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
import plotly.express as px
import plotly.graph_objects as go


st.title("Unmasking Hidden Cyber Threats")
st.write("This is a demo Streamlit app.")

# Load train DataFrame 
df = pd.read_csv('data/cleaned/cleaned_train.csv')

# Create tabs
tab1, tab2 = st.tabs(["📊 Plot", "📋 Data Table"])

with tab1:
    st.header("This is a plot")
    st.line_chart({"data": [1, 5, 2, 6]})

with tab2:
    st.header("This is a data table")
    st.write({"Column A": [1, 2], "Column B": [3, 4]})


fig, ax =plt.subplots(figsize=(12, 5))
sns.displot(data=df["duration"], kde=True)
st.pyplot(fig)
    
# Example DataFrame
data = {
    "src_bytes": [123, 456, 789],
    "dst_bytes": [321, 654, 987]
}
st.write("Sample data:")
st.dataframe(df)





st.title('Top 10 service Types by Class')

fig, ax = plt.subplots(figsize=(12, 5))
sns.countplot(data=df, x='service', hue='class', order=df['service'].value_counts().index[:10])
plt.xticks(rotation=45)
st.pyplot(fig)


# Filter to only anomalous rows
anomalies = df[df['class'] == 'anomaly']

# Optional: Let user choose metric
metric = st.selectbox("Select metric to compare", ['duration'])  # Add more metrics if you like



# CREATE SCATTER PLOT
df = df.reset_index()

# Plot
fig, ax = plt.subplots(figsize=(12, 5))

# Scatter plot
sns.scatterplot(data=df,x=df.index, y='duration', hue='class', ax=ax, alpha=0.5)

ax.set_title("Duration by Index, Colored by Class")
ax.set_xlabel("Index")
ax.set_ylabel("Duration")

st.pyplot(fig)

# CREATE DENSITY PLOT
st.title("Density Plot of Duration by Class")

# Optional: filter extreme outliers if needed
# df = df[df['duration'] < df['duration'].quantile(0.99)]

# Create the plot
fig, ax = plt.subplots(figsize=(10, 5))
sns.kdeplot(data=df, x='duration', hue='class', ax=ax, common_norm=False, fill=True)
ax.set_title("Density Plot of Duration (Normal vs Anomaly)")
ax.set_xlabel("Duration")
ax.set_ylabel("Density")

# Show in Streamlit
st.pyplot(fig)


