import streamlit as st
import pandas as pd
import plotly.express as px
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
    custom_theme = {"primary": "#0e76a8", "bg": "#ffffff", "text": "#262730", "plot_bg": "white"}
else:
    custom_theme = {"primary": "#FF4B4B", "bg": "#0e1117", "text": "#FAFAFA", "plot_bg": "#1e1e1e"}

st.markdown(f"""
    <style>
      .stApp {{ background-color: {custom_theme['bg']}; color: {custom_theme['text']}; }}
      div.stButton > button {{ background-color: {custom_theme['primary']}; color: white; }}
    </style>
    """, unsafe_allow_html=True)

# Dataset toggle
dataset_filter = st.sidebar.radio("Select Dataset", ["Train", "Test", "Both"])
st.sidebar.caption("Use filters to explore subsets of the dataset. Charts will update based on your selection.")

# Data Loading
@st.cache_data
def load_data():
    df_train = pd.read_csv("data/cleaned/cleaned_train.csv")
    df_test = pd.read_csv("data/cleaned/cleaned_test.csv")
    df_train["source"] = "Train"
    df_test["source"] = "Test"
    return pd.concat([df_train, df_test], ignore_index=True)

df = load_data()

# Filter by dataset
if dataset_filter == "Train":
    df_filtered = df[df["source"] == "Train"].copy()
elif dataset_filter == "Test":
    df_filtered = df[df["source"] == "Test"].copy()
else:
    df_filtered = df.copy()

# Sidebar filters
protocol_filter = st.sidebar.multiselect(
    "Protocol Type", df_filtered["protocol_type"].unique(), default=df_filtered["protocol_type"].unique()
)
flag_filter = st.sidebar.multiselect(
    "Flag", df_filtered["flag"].unique(), default=df_filtered["flag"].unique()
)
df_filtered = df_filtered[
    df_filtered["protocol_type"].isin(protocol_filter) & df_filtered["flag"].isin(flag_filter)
]

if df_filtered.empty:
    st.sidebar.warning("No data matches the selected filters.")

# Tabs
tabs = st.tabs(["Project Overview", "Overview", "Traffic Visuals", "Statistical & Model"])
tab_overview, tab_overview2, tab_visuals, tab_model = tabs

# Tab: Project Overview
with tab_overview:
    st.title("Unmasking Hidden Cyber Threats")
    with st.expander("Click to read full project introduction and objectives"):
        st.markdown("""
**Cybersecurity is a top concern for today’s businesses**, just look at recent UK breaches at M&S, Co‑op and Harrods, where a single attack can halt operations, disrupt supply chains and erode customer trust.
To tackle this, we created **Unmasking Hidden Cyber Threats**, an exploratory data project that:

- Builds a clean ETL pipeline to prepare network data
- Uses statistical analysis and AI‑driven storytelling to uncover malicious patterns
- Validates hypotheses to focus on key indicators
- Presents findings in an interactive dashboard for early warning and rapid response

By surfacing anomalies before they strike, our project helps stakeholders move from reactive firefighting to proactive defense.
                    
**Project Objectives**

1. Detect Patterns Behind Cyber Threats  
2. Validate Data-Driven Hypotheses  
3. Build a Predictive Model for Intrusion Detection  
4. Deliver Actionable Insights via Dashboard  
5. Demonstrate AI-Enhanced Analytics  
6. Promote Cybersecurity Awareness  
        """, unsafe_allow_html=True)

# Tab: Overview
with tab_overview2:
    st.header("Overview")
    col1, col2 = st.columns(2)
    col1.metric("Normal Connections", df_filtered[df_filtered["class"] == "normal"].shape[0])
    col2.metric("Anomalous Connections", df_filtered[df_filtered["class"] == "anomaly"].shape[0])
    fig_pie = px.pie(df_filtered, names="class", title="Normal vs Anomalous Traffic")
    fig_pie.update_layout(paper_bgcolor=custom_theme["plot_bg"], font_color=custom_theme["text"])
    st.plotly_chart(fig_pie, use_container_width=True)

# Tab: Traffic Visuals
with tab_visuals:
    st.header("Traffic Visuals")
    # Boxplots
    if df_filtered["class"].nunique() > 1:
        fig1 = px.box(df_filtered, x="class", y="src_bytes", title="src_bytes by Class")
        fig1.update_layout(paper_bgcolor=custom_theme["plot_bg"], font_color=custom_theme["text"])
        st.plotly_chart(fig1, use_container_width=True)
    else:
        st.warning("Not enough class types to plot src_bytes.")

    if df_filtered["class"].nunique() > 1:
        fig2 = px.box(df_filtered, x="class", y="duration", title="Duration by Class")
        fig2.update_layout(paper_bgcolor=custom_theme["plot_bg"], font_color=custom_theme["text"])
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.warning("Not enough class types to plot duration.")

    # Top services chart
    st.subheader("Top 10 Services by Anomaly Count")
    services = df_filtered.groupby(["service", "class"]).size().unstack(fill_value=0)
    services["anomaly"] = services.get("anomaly", 0)
    services["normal"] = services.get("normal", 0)
    top_services = services.sort_values(by="anomaly", ascending=False).head(10).reset_index()
    fig_bar = px.bar(
        top_services,
        x="service",
        y=["normal", "anomaly"],
        title="Top 10 Services by Class",
        labels={"value": "Count", "variable": "Class"}
    )
    fig_bar.update_layout(paper_bgcolor=custom_theme["plot_bg"], font_color=custom_theme["text"])
    st.plotly_chart(fig_bar, use_container_width=True)

    # Heatmap
    st.subheader("Correlation Heatmap")
    fig_hm, ax = plt.subplots(figsize=(10, 6))
    sns.heatmap(df_filtered.select_dtypes("number").corr(), cmap="coolwarm", center=0, ax=ax)
    ax.set_facecolor(custom_theme["plot_bg"])
    st.pyplot(fig_hm)

# Tab: Statistical & Model
with tab_model:
    st.header("Hypotheses & Predictive Model")
    st.markdown("""
- H1: Malicious traffic has higher `src_bytes` (Mann-Whitney U)
- H2: Service type and class are dependent (Chi-square)
- H3: Malicious traffic has shorter `duration` (T-test)
    """, unsafe_allow_html=True)

    df_train_data = df[df["source"] == "Train"].copy()
    def preprocess(dfm):
        dfm = dfm.drop(columns=["source"], errors="ignore")
        for c in dfm.select_dtypes("object").columns:
            dfm[c] = LabelEncoder().fit_transform(dfm[c])
        return dfm

    df_enc = preprocess(df_train_data)
    X = df_enc.drop("class", axis=1)
    y = df_enc["class"]
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_val)

    st.subheader("Classification Report")
    st.text(classification_report(y_val, y_pred))

    st.subheader("Confusion Matrix")
    fig_cm = px.imshow(
        confusion_matrix(y_val, y_pred),
        labels=dict(x="Predicted", y="Actual", color="Count"),
        x=["normal", "anomaly"], y=["normal", "anomaly"], text_auto=True
    )
    fig_cm.update_layout(paper_bgcolor=custom_theme["plot_bg"], font_color=custom_theme["text"])
    st.plotly_chart(fig_cm, use_container_width=True)

    st.subheader("Download Predictions")
    df_test_data = df[df["source"] == "Test"].copy()
    df_test_enc = preprocess(df_test_data)
    df_test_data["prediction"] = clf.predict(df_test_enc.drop("class", axis=1))
    csv = df_test_data.to_csv(index=False).encode("utf-8")
    st.download_button("Download Test Set Predictions", data=csv, file_name="predictions.csv", mime="text/csv")
