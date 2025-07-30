

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
st.title("Cyber Threat Detection Dashboard")
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
    st.subheader("Key Performance Indicators (KPIs)")

    total = len(df)
    norm_count = df['class'].value_counts().get('normal', 0)
    anom_count = df['class'].value_counts().get('anomaly', 0)
    anomaly_rate = anom_count / total if total else 0

# Create two columns
    col1, col2, col3, col4, col5 = st.columns(5)

    # Calculate average durations
    avg_durations = df.groupby("class")["duration"].mean().round(2).to_dict()

# Display with larger font using HTM
with col1:
    st.markdown(
        f"""
        <div style="font-size:30px; text-align:center;">
            <strong>Normal activity</strong><br>{avg_durations.get('normal', 0)} sec
        </div>
        """,
        unsafe_allow_html=True
     )
with col2:
    st.markdown(f"""
        <div style="font-size:30px; text-align:center;">
            <strong>Anomaly Activity</strong><br>{avg_durations.get('anomaly', 0)} sec
        </div>
        """,
        unsafe_allow_html=True
    ) 

    st.markdown("<br>", unsafe_allow_html=True)


with col3:
    st.markdown(
        f"""
        <div style="font-size:30px; text-align:center;">
            <strong>Total Records</strong><br>
            {total}
        </div>
        """,
        unsafe_allow_html=True
    )

with col4:
    st.markdown(
        f"""
        <div style="font-size:30px; text-align:center; color:green;">
            <strong>Normal Connections</strong><br>
            {norm_count} <br>
            <span style="font-size:20px; color:gray;">({norm_count/total:.1%})</span>
        </div>
        """,
        unsafe_allow_html=True
    )


with col5:
    st.markdown(
        f"""
        <div style="font-size:30px; text-align:center; color:crimson;">
            <strong>Anomalous Connections</strong><br>
            {anom_count} <br>
            <span style="font-size:20px; color:gray;">({anomaly_rate:.1%})</span>
        </div>
        """,
        unsafe_allow_html=True
    )





# --- 1. Feature Importance --
    

with tab2:
    st.subheader("Top Features for Predicting Attacks")
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

    st.subheader("Distribution of Features by Class")
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

    st.subheader("Most Used Services: Normal vs Anomaly")
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

# --violin chart---
    st.subheader("Distribution of Connection Duration (Normal vs Anomaly)")

    # Log transform
    df["log_src_bytes"] = np.log1p(df["src_bytes"])

    fig = px.violin(
    df,
    y="log_src_bytes",
    x="class",
    color="class",
    box=True,             # Show mini box plot
    points="all",         # Show all individual points
    title="Violin of log(src_bytes + 1)",
    labels={"class": "Connection Type", "log_src_bytes": "log(src_bytes + 1)"},
    color_discrete_map={"normal": "blue", "anomaly": "crimson"}
)

    st.plotly_chart(fig, use_container_width=True)
 # ---4. correlation heatmap ---

    st.subheader("Correlation Matrix")
    subset_df = df.loc[:, df.columns.str.contains('rate|count|class', case=False)]

    fig4 = plt.figure(figsize=(30, 15))
    sns.heatmap(subset_df.corr(numeric_only=True), annot=True, cmap='coolwarm')
    st.pyplot(fig4)


    st.subheader("Violin Plot: Duration by Class (Normal vs Anomaly)")

with tab3:
    

        # Hypothesis 1
        st.subheader("Hypothesis 1: src_bytes and Attack Status")
        st.markdown("""
        **Null Hypothesis (H₀):** No difference in `src_bytes` between malicious and normal traffic.  
        **Alternative Hypothesis (H₁):** Malicious traffic has higher `src_bytes`.  
        **Test Used:** Mann–Whitney U test (non-parametric, one-tailed)  
        """)
        
        st.write(f"**Result:** U-Statistic = 141833,516.50, p-value = 0.00000 → **Fail to reject H₀**")
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

        st.write(f"**Result:** χ² = 18631.45, Degrees of Freedom = 62, p-value = 0.0000 → **Reject H₀**")
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
      

        st.markdown(f"""
        **Results:**

        | Test                                | Statistic              | p-value  | Conclusion            |
        |-------------------------------------|------------------------|----------|-----------------------|
        | Shapiro–Wilk (Normality)            | non-normal (both)      | —        | used non-parametric   |
        | Levene’s Test (Variance)            | —                      | 0.00000 | unequal variances     |
        | Welch’s T-test (log-duration)       | t = 11.29              | 0.00000 | reject H₀             |
        | Mann–Whitney U                      | U = 85,330,208.5     | 0.00000 | reject H₀             |
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
    # --- Encode categorical features ---
    df = df.copy()
    df["class_encoded"] = df["class"].map({"normal": 0, "anomaly": 1})

    
for col in df.select_dtypes("object").columns:
    if col != "class":
        df[col] = LabelEncoder().fit_transform(df[col])

    
with tab4:
    st.header("Predictive Model")
    st.markdown("""
     - H1: Malicious traffic has higher `src_bytes` (Mann-Whitney U)
     - H2: Service type and class are dependent (Chi-square)
     - H3: Malicious traffic has shorter `duration` (T-test)
    """, unsafe_allow_html=True)
    
    # Encode categorical columns and target
    df_model = df.copy()
    for col in df_model.select_dtypes(include="object").columns:
        df_model[col] = LabelEncoder().fit_transform(df_model[col])

    # Split features and target
    X = df_model.drop("class", axis=1)
    y = df_model["class"]

    # Encode target if still string
    if y.dtype == "object":
        y = LabelEncoder().fit_transform(y)

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42)

    # Train model
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    # Classification Report
    st.subheader("Classification Report")
    st.text(classification_report(y_test, y_pred, target_names=["normal", "anomaly"]))

    # Confusion Matrix
    st.subheader("Confusion Matrix")
    fig_cm = px.imshow(
        confusion_matrix(y_test, y_pred),
        labels=dict(x="Predicted", y="Actual", color="Count"),
        x=["normal", "anomaly"], y=["normal", "anomaly"],
        text_auto=True
    )
    st.plotly_chart(fig_cm, use_container_width=True)

