

import streamlit as st
import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.express as px
import plotly.graph_objects as go
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import MinMaxScaler
from scipy.stats import ttest_ind, mannwhitneyu, levene, shapiro, chi2_contingency
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix

# --- Layout ---
st.set_page_config(page_title="Cyber Threat Visual Dashboard", layout="wide")
st.title("🔍 Cyber Threat Detection Dashboard")
# Load data
df = pd.read_csv("data/cleaned/cleaned_train.csv")

# Glossary for sidebar labels
with st.sidebar.expander("Glossary", expanded=False):
    st.markdown(
        """
**Protocol Type**  
- **tcp**: Transmission Control Protocol  
- **udp**: User Datagram Protocol  
- **icmp**: Internet Control Message Protocol  

**Flag**  
- **SF**: Normal establishment and teardown  
- **S0**: No reply to connection attempt  
- **REJ**: Connection attempt rejected  
- **RSTR**: RST from the remote host  
- **RSTO**: RST from the originator  
- **S1**: Connection established, only one data packet  
- **S2**: Connection established, two data packets  
- **S3**: Connection fully established (three-way handshake)  
- **RSTOS0**: RST after SYN without ACK  
- **SH**: SYN and FIN seen, half-open connection  
- **OTH**: Other states  
""",
        unsafe_allow_html=True,
    )


# --- Preprocessing ---
df['class_encoded'] = df['class'].map({'normal': 0, 'anomaly': 1})
feature_cols = ['count', 'serror_rate', 'srv_serror_rate',
                'dst_host_serror_rate', 'dst_host_srv_rerror_rate']

# Tabs
tab0, tab1, tab2, tab3, tab4 = st.tabs([
    "Project Overview", "KPI & Overview", "Visualizations", "Stats & Tests", "Predictive Model"
])


with tab0:
    st.markdown(
        """
        <style>
          .project-text p { font-size: 18px; line-height: 1.6; }
          .project-text h2 { font-size: 24px; margin-top: 20px; }
          .project-text strong { font-size: 18px; }
          .project-text ol li { font-size: 16px; margin-bottom: 8px; }
        </style>
        <div class="project-text">
          <p>Cybersecurity has become a paramount concern for modern businesses. Recent breaches at UK organisations such as Marks &amp; Spencer, the Co‑operative Group and Harrods demonstrate how a single attack can paralyse operations, disrupt supply chains and undermine customer trust. To shed light on these risks, we present <strong>Unmasking Hidden Cyber Threats</strong>, a data analytics project that uncovers emerging patterns and vulnerabilities.</p>

          <p><strong>Robust ETL Pipeline</strong><br>
          We ingest raw network and log data from multiple sources, apply cleansing rules and transformations, and centralise everything in a scalable data warehouse—ensuring consistency, traceability and performance.</p>

          <p><strong>Advanced Pattern Discovery</strong><br>
          Through a combination of statistical analysis and AI-driven anomaly detection, we isolate irregular activity and craft data-backed narratives that reveal stealthy threat behaviours.</p>

          <p><strong>Hypothesis Validation</strong><br>
          Guided by domain knowledge, we formulate and test targeted hypotheses (e.g. unusual port usage, sudden spikes in failed authentications), iterating quickly to surface the strongest indicators of compromise.</p>

          <p><strong>Interactive Early-Warning Dashboard</strong><br>
          A user-friendly interface visualises key metrics, alerts on emerging threats in real time, and lets security teams drill down into the data for rapid incident investigation.</p>

          <p>By surfacing subtle anomalies before they escalate, <strong>Unmasking Hidden Cyber Threats</strong> empowers organisations to shift from reactive firefighting to proactive defence—protecting operations, supply chains and customer trust.</p>

          <h2>Project Objectives</h2>
          <ol>
            <li>Detect Patterns Behind Cyber Threats</li>
            <li>Validate Data-Driven Hypotheses</li>
            <li>Build a Predictive Model for Intrusion Detection</li>
            <li>Deliver Actionable Insights via Dashboard</li>
            <li>Demonstrate AI-Enhanced Analytics</li>
            <li>Promote Cybersecurity Awareness</li>
          </ol>
        </div>
        """,
        unsafe_allow_html=True
    )

with tab1:
    st.subheader("📌 Key Performance Indicators (KPIs)")

    total = len(df)
    norm_count = df['class'].value_counts().get('normal', 0)
    anom_count = df['class'].value_counts().get('anomaly', 0)
    anomaly_rate = anom_count / total if total else 0

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Records", total)
    col2.metric("Normal Connections", norm_count, delta=f"{norm_count/total:.1%}")
    col3.metric("Anomalous Connections", anom_count, delta=f"{anomaly_rate:.1%}", delta_color="inverse")

    # Optional: Add average duration comparison
# Calculate average durations
avg_durations = df.groupby("class")["duration"].mean().round(2).to_dict()

# Create two columns
col1, col2 = st.columns(2)

# Display with larger font using HTML
with col1:
    st.markdown(
        f"""
        <div style="font-size:25px; text-align:center;">
            <strong>Normal activity</strong><br>{avg_durations.get('normal', 0)} sec
        </div>
        """,
        unsafe_allow_html=True
    )

with col2:
    st.markdown(
        f"""
        <div style="font-size:25px; text-align:center;">
            <strong>Anomaly Activity</strong><br>{avg_durations.get('anomaly', 0)} sec
        </div>
        """,
        unsafe_allow_html=True
    )



# --- 1. Feature Importance ---

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
    title='Feature Importance',
    labels={'Importance': 'Importance Score', 'Feature': 'Feature'}
    )
st.plotly_chart(fig2, use_container_width=True)
st.markdown('Machine learning algorithm Random Forest was use to produce this graph. If the model relies heavily on a feature to make decisions (e.g., duration or serror_rate), that feature gets a higher importance score.')
# -- 2. Distribution of Features by Class --

with tab2:



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
 


 # --- 3. Service Breakdown ---

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

    st.subheader("📈 Correlation Matrix")
    subset_df = df.loc[:, df.columns.str.contains('rate|count|class', case=False)]

    fig4 = plt.figure(figsize=(30, 15))
    sns.heatmap(subset_df.corr(numeric_only=True), annot=True, cmap='coolwarm')
    st.pyplot(fig4)