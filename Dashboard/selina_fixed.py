import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder

# Page Configuration
st.set_page_config(page_title="Unmasking Hidden Cyber Threats", layout="wide")

# Sidebar: Theme and Dataset Selection
theme_mode = st.sidebar.selectbox("Select Theme Mode", ["Light", "Dark"])
if theme_mode == "Light":
    theme = {"primary": "#0e76a8", "bg": "#ffffff", "text": "#262730", "plot_bg": "white"}
else:
    theme = {"primary": "#FF4B4B", "bg": "#0e1117", "text": "#FAFAFA", "plot_bg": "#1e1e1e"}

# Dataset selection
dataset = st.sidebar.radio("Select Dataset", ["Train", "Test", "Both"])
st.sidebar.caption("Use filters to explore subsets; charts update accordingly.")

# Load data
@st.cache_data
def load_data():
    df_tr = pd.read_csv("data/cleaned/cleaned_train.csv")
    df_te = pd.read_csv("data/cleaned/cleaned_test.csv")
    df_tr["source"] = "Train"
    df_te["source"] = "Test"
    return pd.concat([df_tr, df_te], ignore_index=True)

df = load_data()

# Filter dataset
if dataset == "Train":
    df_f = df[df["source"] == "Train"].copy()
elif dataset == "Test":
    df_f = df[df["source"] == "Test"].copy()
else:
    df_f = df.copy()

# Sidebar filters
prot = st.sidebar.multiselect("Protocol Type", df_f["protocol_type"].unique(), default=df_f["protocol_type"].unique())
flag = st.sidebar.multiselect("Flag", df_f["flag"].unique(), default=df_f["flag"].unique())
df_f = df_f[df_f["protocol_type"].isin(prot) & df_f["flag"].isin(flag)]
if df_f.empty:
    st.sidebar.warning("No data matches filters.")

# Tabs
tab_overview, tab1, tab2, tab3 = st.tabs(["Project Overview", "Overview", "Traffic Visuals", "Detailed Analysis", "Model"][:4])

# Project Overview Tab
with tab_overview:
    st.title("Unmasking Hidden Cyber Threats")
    with st.expander("Click to read full project introduction and objectives"):
        st.markdown("""
Cybersecurity has become one of the most critical challenges for modern organisations. As businesses grow more reliant on digital infrastructure, cyberattacks have escalated in scale, sophistication, and impact.

In the UK, high-profile incidents involving companies like **M&S, Co-op, and Harrods** have shown how a single breach can paralyse operations and damage public trust.

**Unmasking Hidden Cyber Threats** is an exploratory data project combining statistical validation, machine learning, and AI-enhanced storytelling to uncover patterns in network activity that may signal intrusions.

---

### Project Objectives

1. Detect Patterns Behind Cyber Threats  
2. Validate Data-Driven Hypotheses  
3. Build a Predictive Model for Intrusion Detection  
4. Deliver Actionable Insights via Dashboard  
5. Demonstrate AI-Enhanced Analytics  
6. Promote Cybersecurity Awareness
        """, unsafe_allow_html=True)

# Overview Tab
with tab1:
    st.header("Overview")
    c1, c2 = st.columns(2)
    c1.metric("Normal Connections", df_f[df_f["class"]=="normal"].shape[0])
    c2.metric("Anomalous Connections", df_f[df_f["class"]=="anomaly"].shape[0])
    fig_pie = px.pie(df_f, names="class", title="Normal vs Anomalous Traffic")
    st.plotly_chart(fig_pie, use_container_width=True)

# Traffic Visuals Tab
with tab2:
    st.header("Traffic Visuals")
    if df_f["class"].nunique() > 1:
        fig1 = px.box(df_f, x="class", y="src_bytes", title="src_bytes by class")
        st.plotly_chart(fig1, use_container_width=True)
        fig2 = px.box(df_f, x="class", y="duration", title="duration by class")
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.warning("Not enough class types for boxplots.")
    services = df_f.groupby(["service","class"]).size().unstack(fill_value=0)
    services["anomaly"] = services.get("anomaly",0)
    services["normal"] = services.get("normal",0)
    top10 = services.sort_values("anomaly",ascending=False).head(10).reset_index()
    fig_bar = px.bar(top10, x="service", y=["normal","anomaly"], title="Top 10 Services by Class")
    st.plotly_chart(fig_bar, use_container_width=True)

# Detailed Analysis Tab
with tab3:
    st.header("Detailed Analysis")
    # Violin plot
    fig_violin = px.violin(df_f, x="class", y=np.log1p(df_f["src_bytes"]), 
                           box=True, points="all", title="Violin of log(src_bytes+1) by class")
    st.plotly_chart(fig_violin, use_container_width=True)
    # Heatmap
    heat = df_f.groupby(["service","class"]).size().unstack(fill_value=0)
    fig_heat = px.imshow(heat, labels=dict(x="Traffic Label", y="Service Type", color="Count"),
                         title="Service vs class", text_auto=True)
    st.plotly_chart(fig_heat, use_container_width=True)
    # Top 5 High-Risk Services
    st.subheader("Top 5 High-Risk Services (100% Anomaly Rate)")
    summary = df_f.groupby("service")["class"].value_counts().unstack(fill_value=0)
    for cls in ["anomaly","normal"]:
        if cls not in summary.columns: summary[cls]=0
    summary["total"] = summary["anomaly"] + summary["normal"]
    summary["anomaly_rate"] = summary["anomaly"]/summary["total"]
    top5 = (summary[summary["total"]>=100]
            [summary["anomaly_rate"]==1.0]
            .sort_values("anomaly", ascending=False)
            .head(5)
            .reset_index())
    top5 = top5[["service","anomaly","normal","total","anomaly_rate"]]
    st.dataframe(top5)

# Model tab omitted for brevity
