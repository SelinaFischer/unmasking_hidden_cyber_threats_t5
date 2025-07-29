



### Introduction:



**Unmasking Hidden Cyber Threats** is a 3-day Hackathon project. We chose this topic because cybersecurity has become one of the most critical challenges facing modern businesses. With the growing sophistication of cyber threats and increasing reliance on digital infrastructure, a single attack can paralyse operations, disrupt supply chains, and erode public trust.

In the UK alone, several high-profile organisations including M&S, Co-op, and Harrods have recently fallen victim to cyberattacks. One particularly severe incident brought M&S’s operations to a complete standstill, leaving shelves empty across stores and highlighting the deep impact these threats can have on daily business continuity.

With this in mind, our team developed *Unmasking Hidden Cyber Threats*, an exploratory data project that applies statistical analysis and AI-enhanced storytelling to uncover patterns in network activity that may indicate malicious behaviour.

Through a clean ETL pipeline, validated hypotheses, and an interactive dashboard built with a **Streamlit app**, the project delivers actionable insights to support early threat detection and faster incident response. Our goal is to empower stakeholders to proactively identify anomalies rather than rely solely on manual detection or reactive defence.



### Objectives

The primary objectives of this project are to:

#### 1. Detect Patterns Behind Cyber Threats
Analyse historical network traffic to uncover patterns and behaviours associated with intrusion attempts and anomalies.

#### 2. Validate Data-Driven Hypotheses
Use statistical testing (Mann-Whitney U, Chi-square, T-test) to verify relationships between connection attributes (e.g. duration, service, flag) and attack types.

#### 3. Build a Predictive Model for Intrusion Detection
Develop and evaluate a classification model to distinguish between normal and malicious connections using features from the dataset.

#### 4. Deliver Actionable Insights via Interactive Dashboard
Design an intuitive Tableau/Streamlit dashboard that allows users to filter, visualise, and explore threat types, feature relationships, and anomaly trends.

#### 5. Demonstrate AI-Enhanced Analytics
Leverage AI tools (e.g. ChatGPT) for code generation, explanation, debugging, and storytelling to accelerate the analytics lifecycle.

#### 6. Promote Cybersecurity Awareness
Translate technical insights into business-friendly recommendations that highlight the importance of early threat detection and data-driven defence strategies.



### Dataset Content

We used the **Network Intrusion Detection** dataset from Kaggle, which contains over 48,000 records of simulated TCP/IP network connections. The dataset is split into two files:

| Dataset         | Rows   | Columns | Label Column | Purpose                                           |
|-----------------|--------|---------|---------------|---------------------------------------------------|
| Train_data.csv  | 25,192 | 42      | `class`       | Used for hypothesis testing and model training    |
| Test_data.csv   | 22,544 | 41      | *(None)*      | Used for prediction and performance evaluation    |

Each connection record includes **41 features**, both numeric and categorical, describing network behaviour such as:

- `duration`, `src_bytes`, `dst_bytes`
- `protocol_type`, `service`, `flag`
- Statistical indicators like `same_srv_rate`, `rerror_rate`, and `dst_host_count`

The `class` label in the training data specifies whether a connection is **normal** or a known **attack type** (e.g. `neptune`, `smurf`, `satan`).

This structure supports both:

- **Hypothesis testing** to detect behavioural differences between normal and attack traffic
- **Predictive modelling**, where we train a classifier on labelled data and evaluate it on unseen test data to simulate real-world threat detection

**Data source**: [Kaggle – Network Intrusion Detection](https://www.kaggle.com/datasets/sampadab17/network-intrusion-detection/data)



### Business Requirements

- Identify suspicious patterns in network traffic for early threat detection  
- Classify connections as normal or anomalous based on their behavior  
- Equip security analysts with a visual, interactive dashboard to support investigation and response  
- Reduce reliance on manual pattern recognition by surfacing statistically validated indicators  


### Hypothesis and how to validate?

## Hypothesis Validation

### Objectives

The objective of hypothesis validation in this project is to apply statistical testing to uncover meaningful behavioural differences between normal and malicious network traffic. This helps identify patterns that could improve early threat detection and support cybersecurity decision-making.

- **Detect Statistical Differences:**  
  Quantify whether key features (such as `src_bytes` or `duration`) show significant differences between normal and malicious traffic.

- **Identify Risk-Associated Attributes:**  
  Determine whether certain categorical features (such as service type) are disproportionately linked to malicious activity.

- **Validate Hypotheses with Statistical Rigor:**  
  Use appropriate hypothesis tests (e.g. Mann-Whitney U, Chi-square, T-test) to ensure findings are statistically valid and not due to random chance.

- **Support Explainable Insights:**  
  Back statistical results with visualisations (e.g. boxplots, heatmaps) to help non-technical stakeholders understand threat patterns.

- **Inform Detection Logic:**  
  Use validated hypotheses to inform detection rules, classification models, or security monitoring strategies.



### Hypothesis 1: Malicious traffic has significantly higher src_bytes than normal traffic


- **Null Hypothesis (H₀):** No difference in `src_bytes` between malicious and normal traffic.  
- **Alternative Hypothesis (H₁):** Malicious traffic has higher `src_bytes`.

**Test Used:**  
Mann-Whitney U test (non-parametric, one-tailed)

**Result:**  
- U-Statistic = 16,002,447.50  
- p-value = 1.00000  
- Conclusion: **Fail to reject H₀**

**Interpretation:**  
There is no significant evidence that malicious traffic sends more data. In fact, visualisation (boxplot and violin plot) suggests the opposite—malicious connections typically have *lower* `src_bytes`, with many near zero. This feature is not a strong indicator of attack behaviour in this dataset.



### Hypothesis 2: Certain service types are more vulnerable to cyberattacks


- **Null Hypothesis (H₀):** No association between service type and whether the traffic is normal or malicious.  
- **Alternative Hypothesis (H₁):** A significant association exists.

**Test Used:**  
Chi-Square Test of Independence (on filtered service counts > 100)

**Result:**  
- Chi-square = 16,903.69  
- Degrees of Freedom = 32  
- p-value = 0.0000  
- Conclusion: **Reject H₀**

**Interpretation:**  
There is a strong statistical association between service type and attack likelihood. Services like `smtp`, `ftp`, `telnet`, and `private` have high anomaly counts. Some legacy services (e.g. `uucp`, `nnsp`) show a 100% anomaly rate, indicating they are exclusive to attack traffic in this dataset.

**Recommendation:**  
Monitor and restrict high-risk service types. Audit legacy services and deprecate if not needed.



### Hypothesis 3: Malicious connections tend to have shorter durations than normal ones


- **Null Hypothesis (H₀):** No difference in connection duration.  
- **Alternative Hypothesis (H₁):** Malicious connections are shorter.

**Tests Used:**
- **T-test (Welch’s, one-tailed)** on log-transformed duration  
- **Mann-Whitney U test** (non-parametric, one-tailed)  

**Results:**
| Test                     | Statistic         | p-value  | Conclusion         |
|--------------------------|------------------|----------|--------------------|
| Shapiro-Wilk (Normality) | Non-normal (both) | —        | Used non-parametric |
| Levene’s Test (Variance) | p = 0.0000        | —        | Unequal variances   |
| T-Test                   | t = -11.29        | 0.0000   | Reject H₀           |
| Mann-Whitney U           | U = 72,505,755.5  | 0.0000   | Reject H₀           |

**Interpretation:**  
Both statistical tests confirm that malicious connections tend to be shorter. Boxplots and log-transformed duration visualisations support this. This insight can be used to inform intrusion detection logic.



### Summary of Hypothesis Results

| Hypothesis | Feature Tested        | Test Used            | Result                | Conclusion                          |
|------------|-----------------------|-----------------------|------------------------|--------------------------------------|
| H1         | `src_bytes`           | Mann-Whitney U        | p = 1.0000             | Not Supported                        |
| H2         | `service` type        | Chi-square            | p < 0.0001             | Supported                            |
| H3         | `duration`            | T-test, Mann-Whitney  | p < 0.0001 (both)      | Supported                            |








## Project Plan
* Outline the high-level steps taken for the analysis.
* How was the data managed throughout the collection, processing, analysis and interpretation steps?
* Why did you choose the research methodologies you used?

## The rationale to map the business requirements to the Data Visualisations
* List your business requirements and a rationale to map them to the Data Visualisations

## Analysis techniques used
* List the data analysis methods used and explain limitations or alternative approaches.
* How did you structure the data analysis techniques. Justify your response.
* Did the data limit you, and did you use an alternative approach to meet these challenges?
* How did you use generative AI tools to help with ideation, design thinking and code optimisation?

## Ethical considerations
* Were there any data privacy, bias or fairness issues with the data?
* How did you overcome any legal or societal issues?

## Dashboard Design
* List all dashboard pages and their content, either blocks of information or widgets, like buttons, checkboxes, images, or any other item that your dashboard library supports.
* Later, during the project development, you may revisit your dashboard plan to update a given feature (for example, at the beginning of the project you were confident you would use a given plot to display an insight but subsequently you used another plot type).
* How were data insights communicated to technical and non-technical audiences?
* Explain how the dashboard was designed to communicate complex data insights to different audiences. 

## Unfixed Bugs
* Please mention unfixed bugs and why they were not fixed. This section should include shortcomings of the frameworks or technologies used. Although time can be a significant variable to consider, paucity of time and difficulty understanding implementation are not valid reasons to leave bugs unfixed.
* Did you recognise gaps in your knowledge, and how did you address them?
* If applicable, include evidence of feedback received (from peers or instructors) and how it improved your approach or understanding.

## Development Roadmap
* What challenges did you face, and what strategies were used to overcome these challenges?
* What new skills or tools do you plan to learn next based on your project experience? 

## Deployment
### Streamlit 

* The App live link is: https://YOUR_APP_NAME.herokuapp.com/ 
* The project was deployed to Streamlit Community Cloud using the following steps.

1. Log in to Streamlit Community Cloud and create an App
2. From the Deploy tab, select GitHub as the deployment method.
3. Select the repository name and click Search. Once it is found, click Connect.
4. Select the branch you want to deploy, then click Deploy Branch.
5. The deployment process should happen smoothly 


## Main Data Analysis Libraries
* Here you should list the libraries you used in the project and provide an example(s) of how you used these libraries.


## Credits 

* In this section, you need to reference where you got your content, media and extra help from. It is common practice to use code from other repositories and tutorials, however, it is important to be very specific about these sources to avoid plagiarism. 
* You can break the credits section up into Content and Media, depending on what you have included in your project. ### Content 

- The text for the Home page was taken from Wikipedia Article A
- Instructions on how to implement form validation on the Sign-Up page was taken from [Specific YouTube Tutorial](https://www.youtube.com/)
- The icons in the footer were taken from [Font Awesome](https://fontawesome.com/)


### Media

- The photos used on the home and sign-up page are from This Open-Source site
- The images used for the gallery page were taken from this other open-source site



## Acknowledgements
* Thank the people who provided support through this project.
