

import streamlit as st
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler
import plotly.express as px
import plotly.graph_objects as go

# Load data
df = pd.read_csv("data/cleaned/cleaned_train.csv")


# --- Preprocessing ---
df['class_encoded'] = df['class'].map({'normal': 0, 'anomaly': 1})
feature_cols = ['count', 'serror_rate', 'srv_serror_rate',
                'dst_host_serror_rate', 'dst_host_srv_rerror_rate']


# --- Layout ---
st.set_page_config(page_title="Cyber Threat Visual Dashboard", layout="wide")
st.title("🔍 Cyber Threat Detection Dashboard")

tab1, tab2, tab3, tab4 = st.tabs(["📊 Distribution of Features", "📈 Feature Importance", "📦 Service Breakdown", "📈 Correlation Heatmap"])

# -- 1. Distribution of Features by Class --

with tab1:
    st.subheader("🔎 Distribution of Features by Class")

    selected_feature = st.selectbox("Select a feature to explore:", feature_cols)

    color_map = {'normal': 'blue', 'anomaly': 'crimson'}

    fig = px.histogram(
        df,
        x=selected_feature,
        color='class',
        color_discrete_map=color_map,
        barmode='overlay',
        nbins=50,
        opacity=0.6,
        labels={'class': 'Connection Type', selected_feature: selected_feature.replace('_', ' ').title()},
        title=f"Distribution of {selected_feature.replace('_', ' ').title()} for Normal vs Cyber Attack"
    )

    fig.update_layout(legend_title_text='Connection Type')
    st.plotly_chart(fig, use_container_width=True)




# --- 2. Feature Importance ---
with tab2:
    st.subheader("📈 Top Features for Predicting Attacks")
    X = df[feature_cols]
    y = df['class_encoded']
    
    model = RandomForestClassifier(random_state=42)
    model.fit(X, y)
    
    importances = model.feature_importances_
    importance_df = pd.DataFrame({
        'Feature': feature_cols,
        'Importance': importances
    }).sort_values(by='Importance', ascending=True)
    
    fig2 = px.bar(
        importance_df,
        x='Importance',
        y='Feature',
        orientation='h',
        title='Feature Importance (Random Forest)',
        labels={'Importance': 'Importance Score', 'Feature': 'Feature'}
    )
    st.plotly_chart(fig2, use_container_width=True)

# --- 3. Service Breakdown ---
with tab3:
    st.subheader("📦 Most Used Services: Normal vs Anomaly")
    service_counts = df.groupby(['service', 'class']).size().unstack(fill_value=0)
    top_services = service_counts.sum(axis=1).sort_values(ascending=False).head(10).index
    filtered_services = service_counts.loc[top_services].reset_index()

    fig3 = px.bar(
        filtered_services,
        x='service',
        y=['normal', 'anomaly'],
        title='Top 10 Services by Class',
        labels={'value': 'Connection Count', 'service': 'Service'},
        barmode='stack'
    )
    st.plotly_chart(fig3, use_container_width=True)

# ---4. correlation heatmap ---

with tab4:
    st.subheader("📈 Correlation Matrix")
    # while heatmap is too large so selecting the columns that indicates positive correlation
    subset_df = df.loc[:, df.columns.str.contains('rate|count|class', case=False)]

    fig4 = plt.figure(figsize=(30, 15))
    sns.heatmap(subset_df.corr(numeric_only=True), annot=True, cmap='coolwarm')
    st.pyplot(fig4)