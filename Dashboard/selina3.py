import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import seaborn as sns
import matplotlib.pyplot as plt
from scipy.stats import ttest_ind, mannwhitneyu, levene, shapiro
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, roc_curve, auc

# Page configuration
st.set_page_config(page_title="Unmasking Hidden Cyber Threats", layout="wide")
st.title("Unmasking Hidden Cyber Threats Dashboard")

# Sidebar controls
dataset = st.sidebar.radio("Select Dataset", ["Train", "Test", "Both"])
st.sidebar.markdown("**Filters (visuals only)**")

# Load the full cleaned datasets
@st.cache_data
def load_full_data():
    df_train = pd.read_csv("data/cleaned/cleaned_train.csv")
    df_test = pd.read_csv("data/cleaned/cleaned_test.csv")
    df_train["source"] = "Train"
    df_test["source"] = "Test"
    return pd.concat([df_train, df_test], ignore_index=True)

df_full = load_full_data()

# Prepare data for visuals/stats
df_vis = df_full.copy()
if dataset == "Train":
    df_vis = df_vis[df_vis["source"] == "Train"]
elif dataset == "Test":
    df_vis = df_vis[df_vis["source"] == "Test"]

# Filters
protocols = st.sidebar.multiselect("Protocol Type", df_full["protocol_type"].unique(), default=df_full["protocol_type"].unique())
flags = st.sidebar.multiselect("Flag", df_full["flag"].unique(), default=df_full["flag"].unique())
df_vis = df_vis[df_vis["protocol_type"].isin(protocols) & df_vis["flag"].isin(flags)]
if df_vis.empty:
    st.sidebar.warning("No data matches filters")

# Feature engineering for visuals
df_vis["log_duration"] = np.log1p(df_vis["duration"])
df_vis["log_src_bytes"] = np.log1p(df_vis["src_bytes"])

# Tabs
tab0, tab1, tab2, tab3, tab4 = st.tabs([
    "Project Overview", "KPI & Overview", "Visualizations", "Stats & Tests", "Model & ROC"
])

# Project Overview
with tab0:
    st.header("Project Overview")
    st.markdown("""
**Objectives**  
- Detect patterns behind cyber threats  
- Validate hypotheses with statistical tests  
- Build a predictive anomaly detection model  
- Deliver interactive dashboard with actionable insights  
- Summarise findings and recommendations  
""")

# KPI & Overview
with tab1:
    total = len(df_vis)
    norm_count = int((df_vis["class"] == "normal").sum())
    anom_count = int((df_vis["class"] == "anomaly").sum())
    st.metric("Total Records", total)
    col1, col2 = st.columns(2)
    col1.metric("Normal", norm_count, delta=f"{norm_count/total:.1%}" if total else "")
    col2.metric("Anomalies", anom_count, delta=f"{anom_count/total:.1%}" if total else "")
    if total > 0:
        fig_pie = px.pie(df_vis, names="class", title="Class Distribution")
        st.plotly_chart(fig_pie, use_container_width=True)

# Visualizations
with tab2:
    st.header("Interactive Visualizations")
    if df_vis["class"].nunique() > 1:
        st.plotly_chart(px.box(df_vis, x="class", y="src_bytes", title="src_bytes (log scale)", log_y=True), use_container_width=True)
        st.plotly_chart(px.box(df_vis, x="class", y="duration", title="duration (log scale)", log_y=True), use_container_width=True)
    else:
        st.warning("Need both classes to show boxplots")
    st.plotly_chart(px.violin(df_vis, x="class", y="log_src_bytes", box=True, points="all", title="Violin of log(src_bytes+1)"), use_container_width=True)
    corr = df_vis.select_dtypes("number").corr()
    fig_hm, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(corr, cmap="coolwarm", center=0, ax=ax)
    st.pyplot(fig_hm)

# Stats & Tests
with tab3:
    st.header("Statistical Tests")
    norm_log = df_vis[df_vis["class"] == "normal"]["log_duration"]
    anom_log = df_vis[df_vis["class"] == "anomaly"]["log_duration"]
    if len(norm_log) >= 3 and len(anom_log) >= 3:
        sn, pn = shapiro(norm_log.sample(min(500, len(norm_log)), random_state=1))
        sa, pa = shapiro(anom_log.sample(min(500, len(anom_log)), random_state=1))
        st.write(f"Shapiro p-values: normal={pn:.4f}, anomaly={pa:.4f}")
        lv_stat, lv_p = levene(norm_log, anom_log)
        st.write(f"Levene p-value: {lv_p:.4f}")
        t_stat, t_p = ttest_ind(anom_log, norm_log, equal_var=False, alternative="less")
        st.write(f"T-test p-value: {t_p:.4f}")
        u_stat, u_p = mannwhitneyu(anom_log, norm_log, alternative="less")
        st.write(f"Mann-Whitney U p-value: {u_p:.4f}")
    else:
        st.write("Not enough data for statistical tests")

# Model & ROC (always train/test split on full data)
with tab4:
    st.header("Predictive Model & ROC Curve")
    # Encode and split full data
    df_model = df_full.copy()
    for col in df_model.select_dtypes("object"):
        df_model[col] = LabelEncoder().fit_transform(df_model[col])
    X = df_model.drop(["class", "source"], axis=1)
    y = (df_model["class"] == "anomaly").astype(int)
    # Ensure both classes exist
    if len(np.unique(y)) > 1:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        clf = RandomForestClassifier(n_estimators=100, random_state=42)
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)
        proba = clf.predict_proba(X_test)[:, list(clf.classes_).index(1)]
        st.metric("Accuracy", f"{accuracy_score(y_test, preds):.2%}")
        st.metric("Precision", f"{precision_score(y_test, preds):.2%}")
        st.metric("Recall", f"{recall_score(y_test, preds):.2%}")
        fpr, tpr, _ = roc_curve(y_test, proba)
        auc_val = auc(fpr, tpr)
        fig_roc = px.area(
            x=fpr, y=tpr,
            title=f"ROC Curve (AUC={auc_val:.3f})",
            labels=dict(x="False Positive Rate", y="True Positive Rate")
        )
        fig_roc.add_shape(type="line", x0=0, x1=1, y0=0, y1=1, line_dash="dash")
        st.plotly_chart(fig_roc, use_container_width=True)
    else:
        st.warning("Full dataset must contain both classes for modeling")