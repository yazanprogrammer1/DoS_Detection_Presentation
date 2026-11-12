# ML-Based DoS Attack Detection and Automated Response (CIC-IDS2017)

A machine-learning intrusion detection system that classifies network flows as **benign** or **DoS attack**, evaluates the classifier on traffic it has never seen, and drives a **simulated automated response** (flow blocking, alerting and firewall IP bans) from the model's predictions.

| | |
|---|---|
| **Threat** | Denial of Service (DoS / DDoS) |
| **Dataset** | CIC-IDS2017 (Canadian Institute for Cybersecurity), `MachineLearningCSV` |
| **Main model** | Random Forest (tuned with 3-fold cross-validation) |
| **Baselines** | Dummy (majority class), Logistic Regression, XGBoost |
| **Test F1 (Wednesday, held-out 20%)** | **0.9989**: Precision 0.9985, Recall 0.9993, FPR 0.07% |
| **Unseen attack (Friday DDoS)** | Recall 0.633 per flow, Precision 0.9994; the response layer still stopped 92% of DDoS flows and banned 30/30 bot IPs |

---

**Author:** Yazan Abu Ali (ID 262305093) · *Applied Machine Learning for Security Analytics* · Instructor: Dr. Khaled Abouelmagd

## Deliverables

| Item | File |
|---|---|
| Research paper | `paper/DoS_Detection_Research_Paper.pdf` (and editable `.docx`) |
| Presentation | `presentation/DoS_Detection_Presentation.pdf` (15 slides) |
| Code | `src/preprocess.py`, `src/train.py`, `src/mitigation.py`, `notebooks/` |
| Trained models | `models/rf_dos_detector.joblib`, `models/xgb_dos_detector.joblib`, `models/model_card.json` |
| Screenshots of real runs | `screenshots/01_…png` to `screenshots/08_…png` |
| Metrics, logs, figures | `results/` |

## 1. Project structure

```
dos-detection/
├── data/
│   ├── raw/                     # original CSVs from CIC-IDS2017 (never modified)
│   └── processed/               # cleaned Parquet files + held-out test split
├── notebooks/
│   ├── 01_eda.ipynb             # exploratory data analysis
│   └── 02_baseline.ipynb        # first split + Dummy / Logistic Regression baselines
├── src/
│   ├── preprocess.py            # cleaning pipeline (same steps for every file)
│   ├── train.py                 # tuning, training, evaluation, error analysis, figures
│   └── mitigation.py            # ML-driven response engine (simulation)
├── models/
│   ├── rf_dos_detector.joblib   # trained Random Forest (main model)
│   ├── xgb_dos_detector.joblib  # trained XGBoost (comparison)
│   └── model_card.json          # hyper-parameters, feature list, metrics, versions
├── results/                     # metrics CSVs, logs, firewall rules, figures/
├── screenshots/                 # screenshots of real runs
├── paper/                       # research paper
├── presentation/                # slides
├── LEARNING_NOTES.md            # concept notes and Q&A
└── requirements.txt
```

## 2. Setup

Requires Python 3.11.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

Download `MachineLearningCSV.zip` from https://www.unb.ca/cic/datasets/ids-2017.html and copy these two files into `data/raw/`:
- `Wednesday-workingHours.pcap_ISCX.csv` (DoS Hulk, GoldenEye, Slowloris, Slowhttptest)
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (DDoS LOIC)

## 3. How to run

```powershell
python src/preprocess.py                         # 1. clean data      (~1 min)
python src/train.py                              # 2. tune/train/eval (~5 min)
python src/mitigation.py                         # 3. response demo on unseen Wednesday flows
python src/mitigation.py --source friday         #    response demo on unseen DDoS
python src/mitigation.py --flows 0 --quiet       #    replay the whole test set, summary only
```

## 4. Data and preprocessing

| Step | Reason | Wednesday | Friday |
|---|---|---|---|
| Raw flows | | 692,703 | 225,745 |
| Strip column names | the original headers have leading spaces | | |
| Drop `Heartbleed` (11 flows) | information-disclosure bug, not DoS; too few samples | | |
| Drop 10 constant columns | zero variance means zero information | | |
| Drop `Fwd Header Length.1` | duplicated column (known CICFlowMeter bug) | | |
| Drop `Destination Port` | prevents shortcut learning ("port 80 = attack") | | |
| Remove rows with `inf`/`NaN` | division by zero when flow duration is 0 | −1,297 | −34 |
| Remove exact duplicates | prevents train/test leakage (25% of Hulk flows were duplicates) | −106,415 | −4,447 |
| **Clean flows / features** | | **584,980 / 66** | **221,264 / 66** |

The cleaning rules were chosen from Wednesday only and applied unchanged to Friday, so no decision was made after looking at test data.

**Split:** Wednesday is split 80/20 (467,984 / 116,996 flows), **stratified by attack type**, with `random_state=42`. Hyper-parameters are tuned with 3-fold CV inside the training portion only. Friday is used only once, as an out-of-distribution test.

## 5. Results

### 5.1 Held-out Wednesday test set (116,996 flows never used for training or tuning)

| Model | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC | FP | FN |
|---|---|---|---|---|---|---|---|---|
| Dummy (majority) | 0.6688 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.5000 | 0 | 38,749 |
| Logistic Regression | 0.9768 | 0.9520 | 0.9793 | 0.9654 | 0.0245 | 0.9979 | 1,915 | 804 |
| **Random Forest** | **0.9993** | **0.9985** | **0.9993** | **0.9989** | **0.0007** | **1.0000** | **57** | **29** |
| XGBoost | 0.9996 | 0.9989 | 0.9998 | 0.9994 | 0.0005 | 1.0000 | 43 | 7 |

Detection rate per attack type:

| Label | Test flows | Logistic Regression | Random Forest | XGBoost |
|---|---|---|---|---|
| BENIGN (correctly allowed) | 78,247 | 97.55% | 99.93% | 99.95% |
| DoS Hulk | 34,569 | 98.64% | 99.93% | 99.99% |
| DoS GoldenEye | 2,057 | 94.75% | 100.00% | 99.90% |
| DoS Slowhttptest | 1,046 | 88.34% | 99.90% | 100.00% |
| DoS slowloris | 1,077 | 90.44% | 99.63% | 99.72% |

### 5.2 Generalisation to an unseen attack (Friday DDoS, 221,264 flows)

| Model | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Logistic Regression | 0.9843 | 0.6360 | 0.7727 | 0.0140 |
| **Random Forest** | **0.9994** | **0.6332** | **0.7752** | **0.0005** |
| XGBoost | 0.9981 | 0.1132 | 0.2033 | 0.0003 |

**Why Random Forest is the main model:** XGBoost is marginally better on the Wednesday test set (7 vs 29 missed attacks), but it collapses on the unseen DDoS attack (11% vs 63% recall). Random Forest gives the best balance: near-perfect results on known DoS types, the best F1 on the unseen attack, and 26× fewer false alarms than Logistic Regression on Friday.

### 5.3 Error analysis (Random Forest, Wednesday test)

- Only 86 errors out of 116,996 flows: 29 missed attacks (24 Hulk, 4 slowloris, 1 Slowhttptest) and 57 false alarms.
- **Almost all errors are flows in which the server sent no payload back** (median backward packet length = 0 for both FN and FP, compared with about 1,900 bytes for true attacks). Without a server response, an attack connection and an aborted benign connection have nearly identical statistics, so the errors come from genuine ambiguity in the features.
- The model is **uncertain on its errors**: mean attack probability is 0.29 for FN and 0.83 for FP, compared with 0.999 for correct detections. This is why the response engine uses a separate ALERT band.
- The most important features are backward packet length statistics (std, mean, segment size): DoS tools leave server responses empty, truncated or uniform.
- The generalisation gap on Friday shows that a supervised model only partly recognises attack variants it was not trained on. This is a known limitation, and the remedy is periodic retraining with new attack samples.

Detailed files: `results/metrics_*.csv`, `results/per_attack_type_wednesday.csv`, `results/misclassified_flows.csv`, `results/error_profile.csv`, `results/rf_tuning_cv.csv`.

### 5.4 Figures (`results/figures/`)

| File | Content |
|---|---|
| `01_label_distribution.png` | class imbalance (log scale) |
| `cm_rf_wednesday.png`, `cm_logreg_wednesday.png`, `cm_rf_friday.png` | confusion matrices |
| `model_comparison.png` | precision / recall / F1 of each model |
| `roc_pr_curves.png` | zoomed ROC (log FPR) and precision-recall curves |
| `generalisation_gap.png` | recall on seen vs unseen attacks |
| `feature_importance.png` | top 20 Random Forest features |
| `error_confidence.png` | model probability for FN and FP |

## 6. Automated response (mitigation simulation)

`src/mitigation.py` replays unseen flows as a live stream in micro-batches of 250 flows. **Every detection decision comes from the Random Forest.** The engine then applies a response policy to the model's attack probability *p*:

| Model output | Action |
|---|---|
| p ≥ 0.90 | **BLOCK_FLOW**: drop the connection and add a strike to the source IP |
| 0.50 ≤ p < 0.90 | **ALERT**: notify the SOC analyst, rate-limit the source, add a strike |
| p < 0.50 | **ALLOW** |
| 3 strikes | **BAN** the IP for 10 min: generate `iptables` and `netsh` firewall rules; later flows from that IP are dropped before reaching the model |
| Whitelisted IP (DNS server) | never banned, to avoid a self-inflicted DoS |

Outputs: `results/mitigation_log.csv` (every decision), `results/alerts.json`, `results/firewall_rules.txt` (commands are **written, not executed**).

| Run (3,000 flows) | Attack flows stopped | Benign wrongly stopped | Attacker IPs banned | Innocent IPs banned |
|---|---|---|---|---|
| Wednesday (unseen test flows) | 994 / 994 (100%) | 1 / 2,006 (0.05%) | 5 / 5 | 0 |
| Friday DDoS (unseen attack) | 1,602 / 1,736 (92.3%) | 0 / 1,264 | 30 / 30 | 0 |

The strike-based IP ban makes the system more robust than the per-flow model alone: on Friday the model detects only about 63% of individual DDoS flows, but the bots are banned after a few detections, so 92% of their traffic is stopped. A single false positive (one benign flow in the Wednesday run) never reaches 3 strikes, so no legitimate user is banned.

> **Simulation note:** the `MachineLearningCSV` files contain no IP addresses, so source IPs are simulated (attackers from a small attacker or botnet pool, benign traffic from 41 office hosts). The IP-ban results therefore show how the response logic behaves; they are not a measurement on real IP data.

## 7. Limitations

- CIC-IDS2017 contains known labelling and flow-construction errors (Engelen et al., 2021). Results on the corrected dataset may differ.
- Lab-generated traffic is cleaner than real networks, so near-perfect in-distribution scores are optimistic.
- Recall on an unseen attack type (DDoS) drops to 63%, so the model needs retraining as attacks evolve, and it could be complemented by an anomaly detector.
- Flow features are computed after a flow ends, so very slow attacks are detected only after their (long) flow times out.

## 8. Reproducibility

Fixed seeds (`42` for split/models, `7` for the simulation), pinned package versions in `requirements.txt`, and the full configuration in `models/model_card.json`. Re-running `preprocess.py` and then `train.py` reproduces every number in this README.
