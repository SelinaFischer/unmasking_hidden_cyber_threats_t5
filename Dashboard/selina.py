
# app.py

import streamlit as st
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import plotly.express as px
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import numpy as np
import io

# Page config
    st.set_page_config(page_title="Unmasking Hidden Cyber Threats", layout="wide")

# Theme toggle
theme_mode = st.sidebar.selectbox("🌓 Select Theme Mode", ["Light", "Dark"])

# Theme color styles
if theme_mode == "Light":
    custom_theme = {
        "primary": "#0e76a8",
        "bg": "#ffffff",
        "text": "#262730",
        "sidebar_bg": "#f0f2f6",
        "plot_bg": "white",
        "grid": "#e1e5eb"
    }
    else:
    custom_theme = {
        "primary": "#FF4B4B",
        "bg": "#0e1117",
        "text": "#FAFAFA",
        "sidebar_bg": "#262730",
        "plot_bg": "#1e1e1e",
        "grid": "#444"
    }

    st.markdown(f"""
    <style>
    .stApp {{
        background-color: {custom_theme['bg']};
        color: {custom_theme['text']};
    }}
    div.stButton > button {{
        background-color: {custom_theme['primary']};
        color: white;
    }}
    </style>
""", unsafe_allow_html=True)

# Load and merge datasets
@st.cache_data
def load_data():
    df_train = pd.read_csv("data/cleaned/cleaned_train.csv")
    df_test = pd.read_csv("data/cleaned/cleaned_test.csv")
    df_train["source"] = "Train"
    df_test["source"] = "Test"
    df_all = pd.concat([df_train, df_test], ignore_index=True)
    return df_all

df = load_data()

# Dataset toggle
dataset_filter = st.sidebar.radio("📁 Select Dataset", options=["Train", "Test", "Both"])
if dataset_filter != "Both":
    df_filtered = df[df["source"] == dataset_filter]
    else:
    df_filtered = df.copy()

# Sidebar Filters
protocol_filter = st.sidebar.multiselect("Protocol Type", df_filtered["protocol_type"].unique(), df_filtered["protocol_type"].unique())
flag_filter = st.sidebar.multiselect("Flag", df_filtered["flag"].unique(), df_filtered["flag"].unique())
    st.sidebar.caption("Use filters to explore subsets of the dataset. Charts will update based on your selection.")
df_filtered = df_filtered[df_filtered["protocol_type"].isin(protocol_filter) & df_filtered["flag"].isin(flag_filter)]
if df_filtered.empty:
    st.warning("No data matches the selected filters. Please broaden your selections.")

# Tabs
tab0, tab1, tab2, tab3, tab4 = st.tabs(["Project Overview", "Overview", "Traffic Visuals", "Statistical Insights", "Model & Prediction"])


with tab0:
    st.title("📘 Unmasking Hidden Cyber Threats")

    
    st.markdown(
    """
    <style>
    summary {
        font-size: 1.1rem;
        font-weight: 600;
        background-color: #e3f2fd;
        padding: 8px;
        border-radius: 5px;
        cursor: pointer;
    }
    details[open] summary {
        background-color: #c8e6c9;
    }
    </style>
    """,
    unsafe_allow_html=True
)

with st.expander("Click to read full project introduction and objectives"):
        st.markdown("""
Cybersecurity has become one of the most critical challenges for modern organisations. As businesses grow more reliant on digital infrastructure, cyberattacks have escalated in scale, sophistication, and impact.

In the UK, high-profile incidents involving companies like **M&S, Co-op, and Harrods** have shown how a single breach can paralyse operations and damage public trust. One particularly severe case saw M&S's entire operations grind to a halt, leaving shelves empty and stores inoperable.

**Unmasking Hidden Cyber Threats** is an exploratory data project combining statistical validation, machine learning, and AI-enhanced storytelling to uncover patterns in network activity that may signal cyber intrusions.

This interactive Streamlit dashboard empowers security analysts with tools to detect anomalies early, reducing reliance on manual investigation and reactive defence.

---

### 🎯 Project Objectives

- **Detect Patterns Behind Cyber Threats**  
  Analyse historical network traffic to uncover behaviours linked to intrusion attempts.

- **Validate Data-Driven Hypotheses**  
  Use statistical testing (Mann-Whitney U, Chi-square, T-test) to assess links between features (e.g., duration, service type) and attack classes.

- **Build a Predictive Model for Intrusion Detection**  
  Train and evaluate a machine learning model to classify connections as normal or malicious.

- **Deliver Actionable Insights via Dashboard**  
  Provide filters, charts, and interactivity to support threat investigation.

- **Demonstrate AI-Enhanced Analytics**  
  Use tools like ChatGPT for code assistance, testing, and storytelling.

- **Promote Cybersecurity Awareness**  
  Translate insights into stakeholder-ready recommendations for proactive data-driven defence.
        """, unsafe_allow_html=True)


# --- Tab 1: Overview ---
with tab1:
    st.header("Overview")
    col1, col2 = st.columns(2)
    normal_count = df_filtered[df_filtered["class"] == "normal"].shape[0]
    anomaly_count = df_filtered[df_filtered["class"] == "anomaly"].shape[0]
    with col1:
        st.metric("Normal Connections", normal_count)
    with col2:
        st.metric("Anomalous Connections", anomaly_count)
    fig = px.pie(df_filtered, names='class', title='Normal vs Anomalous Traffic')
    fig.update_layout(paper_bgcolor=custom_theme["plot_bg"], font_color=custom_theme["text"])
    st.plotly_chart(fig, use_container_width=True)

# --- Tab 2: Traffic Visuals ---
with tab2:
    st.header("📉 Traffic Visual Comparison")
    col3, col4 = st.columns(2)
    with col3:
        
    if df_filtered["class"].nunique() > 1:
    fig1 = px.box(df_filtered, x="class", y="src_bytes", title="src_bytes by Class")
    fig1.update_layout(paper_bgcolor=custom_theme["plot_bg"], font_color=custom_theme["text"])
    st.plotly_chart(fig1, use_container_width=True)
    else:
    st.warning("Not enough class types to draw boxplot for 'src_bytes'. Please select a broader filter.")

    with col4:
        
    if df_filtered["class"].nunique() > 1:
    fig2 = px.box(df_filtered, x="class", y="duration", title="Duration by Class")
    fig2.update_layout(paper_bgcolor=custom_theme["plot_bg"], font_color=custom_theme["text"])
    st.plotly_chart(fig2, use_container_width=True)
    else:
    st.warning("Not enough class types to draw boxplot for 'duration'. Please select a broader filter.")


    st.subheader(" Top Services by Anomalous Traffic")
    top_services = df_filtered.groupby(['service', 'class']).size().unstack().fillna(0)
    fig3 = top_services.sort_values(by='anomaly', ascending=False).head(10).plot(kind='bar', stacked=True, figsize=(10, 5))
    plt.title("Top 10 Services by Class")
    plt.xlabel("Service")
    plt.ylabel("Count")
    st.pyplot(plt.gcf())

    st.subheader(" Correlation Heatmap")
    fig4, ax4 = plt.subplots(figsize=(12, 6))
    numeric_cols = df_filtered.select_dtypes(include='number')
    sns.heatmap(numeric_cols.corr(), cmap='coolwarm', center=0, ax=ax4)
    st.pyplot(fig4)

# --- Tab 3: Statistical Insights ---
with tab3:
    st.header("📈 Hypotheses Validation")
    st.markdown("""
    - **H1**: Malicious traffic has significantly higher `src_bytes` – *Mann-Whitney U test*
    - **H2**: Certain `service` types are more vulnerable – *Chi-square test*
    - **H3**: Malicious connections have shorter `duration` – *T-test*
    """)
    st.info("Statistical testing was performed in Jupyter Notebook. Key findings are visualized in the 'Traffic Visuals' tab.")

# --- Tab 4: Model & Prediction ---
with tab4:
    st.header("🤖 Predictive Model: Random Forest")

    def preprocess(df_model):
        df_model = df_model.copy()
        drop_cols = ["label", "source"]
        df_model = df_model.drop(columns=[col for col in drop_cols if col in df_model.columns])
        label_encoders = {}
        for col in df_model.select_dtypes(include='object').columns:
            le = LabelEncoder()
            df_model[col] = le.fit_transform(df_model[col])
            label_encoders[col] = le
        return df_model, label_encoders

    df_encoded, encoders = preprocess(df[df["source"] == "Train"])
    X = df_encoded.drop("class", axis=1)
    y = df_encoded["class"]
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_val)

    st.subheader("Classification Report")
    st.text(classification_report(y_val, y_pred))

    st.subheader("Confusion Matrix")
    fig_cm, ax_cm = plt.subplots()
    sns.heatmap(confusion_matrix(y_val, y_pred), annot=True, fmt='d', cmap='Blues', 
                xticklabels=["Normal", "Anomaly"], yticklabels=["Normal", "Anomaly"])
    ax_cm.set_xlabel("Predicted")
    ax_cm.set_ylabel("Actual")
    st.pyplot(fig_cm)

    # Prediction on full test set
    st.subheader("Downloadable Predictions")
    df_test_input, _ = preprocess(df[df["source"] == "Test"])
    X_test = df_test_input.drop("class", axis=1)
    test_preds = clf.predict(X_test)
    df_output = df[df["source"] == "Test"].copy()
    df_output["prediction"] = test_preds
    csv = df_output.to_csv(index=False).encode('utf-8')
    st.download_button("Download Test Set Predictions", data=csv, file_name="test_predictions.csv", mime="text/csv")
