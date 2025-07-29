import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.preprocessing import MinMaxScaler

# Load data
df = pd.read_csv("data/cleaned/cleaned_train.csv")

# Title
st.title("🔍 Cyber Threat Detection Dashboard")

# Sidebar
st.sidebar.header("Feature Selection")
features_to_plot = [
    'count', 'serror_rate', 'srv_serror_rate',
    'dst_host_serror_rate', 'dst_host_srv_rerror_rate'
]
selected_feature = st.sidebar.selectbox("Select a feature to visualize", features_to_plot)
class_filter = st.sidebar.multiselect("Filter by Class", df['class'].unique(), default=df['class'].unique())




#  Add a Feature Importance Section
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import numpy as np

# Encode class column
df_model = df.copy()
le = LabelEncoder()
df_model['class_encoded'] = le.fit_transform(df_model['class'])  # anomaly = 1, normal = 0

# Select only numeric columns for the model
X = df_model.select_dtypes(include=[np.number]).drop(columns=['class_encoded'])
y = df_model['class_encoded']

# Fit Random Forest
X_train, X_test, y_train, y_test = train_test_split(X, y, stratify=y, test_size=0.2, random_state=42)
rf = RandomForestClassifier(random_state=42)
rf.fit(X_train, y_train)

# Get feature importance
importances = rf.feature_importances_
feature_importance_df = pd.DataFrame({'Feature': X.columns, 'Importance': importances})
feature_importance_df = feature_importance_df.sort_values(by='Importance', ascending=False).head(5)


# Display KIP card 
st.markdown("## 📌 Top 5 Features Predicting Abnormal Activity")

# Get the top 5 features (or fewer if not enough)
num_kpis = min(5, len(feature_importance_df))  
top_features = feature_importance_df.head(num_kpis)


# Create the correct number of columns
kpi_cols = st.columns(num_kpis)

for i in range(num_kpis):
    row = feature_importance_df.iloc[i]
    kpi_cols[i].metric(label=row['Feature'], value=f"{row['Importance']:.3f}")



# Filtered Data
filtered_df = df[df['class'].isin(class_filter)]

# Section: Service vs Class
st.subheader("📌 Service Distribution by Class")
top_services = filtered_df['service'].value_counts().nlargest(10).index
service_df = filtered_df[filtered_df['service'].isin(top_services)]
fig1 = px.histogram(service_df, x='service', color='class', barmode='group')
st.plotly_chart(fig1)

# Section: Feature Distribution
st.subheader(f"🔍 Distribution of {selected_feature} by Class")
fig2 = px.histogram(filtered_df, x=selected_feature, color='class', marginal='box', nbins=50)
st.plotly_chart(fig2)

# Section: Box Plot
st.subheader(f"📊 Box Plot of {selected_feature} by Class")
fig3 = px.box(filtered_df, x='class', y=selected_feature, points="all")
st.plotly_chart(fig3)

# Section: Parallel Coordinates
st.subheader("🕸️ Parallel Coordinates Plot")
subset = filtered_df[features_to_plot + ['class']].copy()
subset['class_encoded'] = subset['class'].astype('category').cat.codes
scaler = MinMaxScaler()
scaled = scaler.fit_transform(subset[features_to_plot])
scaled_df = pd.DataFrame(scaled, columns=features_to_plot)
scaled_df['class'] = subset['class']
fig4 = px.parallel_coordinates(scaled_df, color=scaled_df['class'].astype('category').cat.codes,
                               dimensions=features_to_plot,
                               color_continuous_scale=px.colors.diverging.Tealrose,
                               labels={col: col.replace("_", " ") for col in features_to_plot})
st.plotly_chart(fig4)

# Section: Scatter Matrix
st.subheader("🧪 Scatter Matrix of Key Features")
fig5 = px.scatter_matrix(filtered_df, dimensions=features_to_plot, color='class')
st.plotly_chart(fig5)
