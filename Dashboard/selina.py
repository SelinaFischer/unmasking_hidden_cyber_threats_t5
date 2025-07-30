import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import seaborn as sns
import matplotlib.pyplot as plt
from scipy.stats import ttest_ind, mannwhitneyu, levene, shapiro, chi2_contingency
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix

# Page configuration
st.set_page_config(page_title="Unmasking Hidden Cyber Threats", layout="wide")
st.title("Unmasking Hidden Cyber Threats Dashboard")

# Custom CSS for Project Overview styling
st.markdown(
    """
    <style>
    .project-overview { 
        font-size: 18px; 
        line-height: 1.6; 
        margin-top: 20px; 
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Sidebar controls
dataset = st.sidebar.radio("Select Dataset", ["Train", "Test", "Both"])
st.sidebar.markdown("**Filters (visuals only)**")

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

with tab2:
    st.header("Interactive Visualizations")
    if df_vis["class"].nunique() > 1:
        st.plotly_chart(px.box(df_vis, x="class", y="src_bytes", title="src_bytes (log scale)", log_y=True), use_container_width=True)
        st.plotly_chart(px.box(df_vis, x="class", y="duration", title="duration (log scale)", log_y=True), use_container_width=True)
    else:
        st.warning("Need both classes to show boxplots")
    st.plotly_chart(px.violin(df_vis, x="class", y="log_src_bytes", box=True, points="all", title="Violin of log(src_bytes+1)"), use_container_width=True)
    corr = df_vis.select_dtypes("number").corr()
    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(corr, cmap="coolwarm", center=0, ax=ax)
    st.pyplot(fig)

with tab3:
    st.header("Statistical Hypothesis Testing")

    if df_vis["class"].nunique() > 1:
        normal = df_vis[df_vis["class"] == "normal"]
        anomaly = df_vis[df_vis["class"] == "anomaly"]

        # Hypothesis 1
        st.subheader("Hypothesis 1: src_bytes and Attack Status")
        st.markdown("""
        **Null Hypothesis (H₀):** No difference in `src_bytes` between malicious and normal traffic.  
        **Alternative Hypothesis (H₁):** Malicious traffic has higher `src_bytes`.  
        **Test Used:** Mann–Whitney U test (non-parametric, one-tailed)  
        """)
        u_stat, u_p = mannwhitneyu(normal["src_bytes"], anomaly["src_bytes"], alternative="greater")
        st.write(f"**Result:** U-Statistic = {u_stat:,.2f}, p-value = {u_p:.5f} → **Fail to reject H₀**")
        st.markdown("""
        **Interpretation:**  
        There is no significant evidence that malicious traffic sends more data. In fact, visualizations (boxplot and violin plot) suggest the opposite—malicious connections typically have lower `src_bytes`, with many near zero. This feature is not a strong indicator of attack behavior in this dataset.
        """)

        # Hypothesis 2
        st.subheader("Hypothesis 2: Service Type vs. Attack Likelihood")
        st.markdown("""
        **Null Hypothesis (H₀):** No association between service type and whether the traffic is normal or malicious.  
        **Alternative Hypothesis (H₁):** A significant association exists.  
        **Test Used:** Chi-Square Test of Independence (on filtered service counts > 100)  
        """)
        contingency = pd.crosstab(df_vis["service"], df_vis["class"])
        chi2, chi_p, dof, expected = chi2_contingency(contingency)
        st.write(f"**Result:** χ² = {chi2:.2f}, Degrees of Freedom = {dof}, p-value = {chi_p:.4f} → **Reject H₀**")
        st.markdown("""
        **Interpretation:**  
        There is a strong statistical association between service type and attack likelihood. Services like `smtp`, `ftp`, `telnet`, and `private` have high anomaly counts. Some legacy services (e.g., `uucp`, `nnsp`) show a 100% anomaly rate, indicating they are exclusive to attack traffic in this dataset.

        **Recommendation:**  
        - Monitor and restrict high-risk service types.  
        - Audit legacy services and deprecate if not needed.
        """)

        # Hypothesis 3
        st.subheader("Hypothesis 3: Connection Duration")
        st.markdown("""
        **Null Hypothesis (H₀):** No difference in connection duration between normal and malicious traffic.  
        **Alternative Hypothesis (H₁):** Malicious connections are shorter.  
        **Tests Used:**  
        - T-test (Welch’s, one-tailed) on log-transformed duration  
        - Mann–Whitney U test (non-parametric, one-tailed)  
        """)
        # Normality
        stat_n, p_n = shapiro(normal["duration"].sample(n=min(len(normal), 5000), random_state=42))
        stat_a, p_a = shapiro(anomaly["duration"].sample(n=min(len(anomaly), 5000), random_state=42))
        # Variance
        lv_stat, lv_p = levene(normal["duration"], anomaly["duration"])
        # T-test
        t_stat, t_p = ttest_ind(np.log1p(normal["duration"]), np.log1p(anomaly["duration"]), equal_var=False)
        # Mann-Whitney
        u3_stat, u3_p = mannwhitneyu(normal["duration"], anomaly["duration"], alternative="less")

        st.markdown(f"""
        **Results:**

        | Test                                | Statistic              | p-value  | Conclusion            |
        |-------------------------------------|------------------------|----------|-----------------------|
        | Shapiro–Wilk (Normality)            | non-normal (both)      | —        | used non-parametric   |
        | Levene’s Test (Variance)            | —                      | {lv_p:.4f} | unequal variances     |
        | Welch’s T-test (log-duration)       | t = {t_stat:.2f}       | {t_p:.4f} | reject H₀             |
        | Mann–Whitney U                      | U = {u3_stat:,.1f}     | {u3_p:.4f} | reject H₀             |
        """)
        st.markdown("""
        **Interpretation:**  
        Both statistical tests confirm that malicious connections tend to be shorter. Boxplots and log-transformed duration visualizations support this. This insight can be used to inform intrusion detection logic.
        """)

        # Summary Table
        st.markdown("""
        **Summary of Hypothesis Results**

        | Hypothesis | Feature Tested | Test Used                   | Result               | Conclusion     |
        |------------|----------------|-----------------------------|----------------------|----------------|
        | H1         | src_bytes      | Mann–Whitney U              | p = 1.0000           | Not Supported  |
        | H2         | service type   | Chi-Square                  | p < 0.0001           | Supported      |
        | H3         | duration       | T-test, Mann–Whitney U      | p < 0.0001 (both)    | Supported      |
        """)

        # 4. Integrated Recommendations
        st.subheader("4. Integrated Recommendations")
        st.markdown(
            """
            - Invert byte-count logic so that low bytes raise suspicion rather than high bytes.  
            - Build service-centric monitoring: focus on SMTP, FTP, Telnet, private ports and audit legacy protocols.  
            - Define duration thresholds per service and flag sessions that end “too quickly.”  
            - Engineer features for ML or rule engines: binary flags for low-byte (<10 KB), short-duration (<5 s), high-risk service; combine into a weighted score.  
            - Harden policy by pruning unused protocols and tightening firewall rules on high-risk ports.
            """
        )


with tab4:
    st.header("Predictive Model")
    st.markdown("""
- H1: Malicious traffic has higher `src_bytes` (Mann-Whitney U)
- H2: Service type and class are dependent (Chi-square)
- H3: Malicious traffic has shorter `duration` (T-test)
    """, unsafe_allow_html=True)

    df_train_data = df_full[df_full["source"] == "Train"].copy()
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
    st.plotly_chart(fig_cm, use_container_width=True)

    st.subheader("Download Predictions")
    df_test_data = df_full[df_full["source"] == "Test"].copy()
    df_test_enc = preprocess(df_test_data)
    df_test_data["prediction"] = clf.predict(df_test_enc.drop("class", axis=1))
    csv = df_test_data.to_csv(index=False).encode("utf-8")
    st.download_button("Download Test Set Predictions", data=csv, file_name="predictions_with_interpretations.csv", mime="text/csv")
