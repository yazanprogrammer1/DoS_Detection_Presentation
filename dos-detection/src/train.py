"""
train.py - Train, tune, compare and evaluate DoS detection models.

Steps
-----
1. Load the cleaned Wednesday data (DoS attacks) and split 80/20 (stratified by attack type).
2. Tune Random Forest hyper-parameters with 3-fold cross-validation on the TRAINING set only.
3. Train 4 models: Dummy, Logistic Regression, Random Forest, XGBoost.
4. Evaluate every model on the held-out Wednesday test set (never seen during training/tuning).
5. Generalisation test: evaluate on Friday DDoS traffic (a different day + an attack type never trained on).
6. Error analysis for the chosen model (Random Forest) + figures.
7. Save the model and its metadata to models/.

Usage (from the dos-detection folder):
    python src/train.py
"""
import json
import time
from datetime import datetime
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")                     # save figures without opening windows
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
import xgboost
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             f1_score, precision_recall_curve, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

# ---------------------------------------------------------------- paths & settings
ROOT = Path(__file__).resolve().parents[1]
PROC = ROOT / "data" / "processed"
MODELS = ROOT / "models"
RES = ROOT / "results"
FIG = RES / "figures"
SEED = 42

# Colours (one fixed colour per model, used in every figure)
COLORS = {"Dummy": "#8a8984", "Logistic Regression": "#2a78d6",
          "Random Forest": "#1baf7a", "XGBoost": "#eb6834"}
plt.rcParams.update({"figure.dpi": 110, "axes.spines.top": False,
                     "axes.spines.right": False, "axes.grid": True,
                     "grid.alpha": 0.25, "font.size": 10})


def banner(text):
    print("\n" + "=" * 70 + f"\n {text}\n" + "=" * 70)


# ---------------------------------------------------------------- 1. data
def load_split():
    df = pd.read_parquet(PROC / "wednesday_clean.parquet")
    X = df.drop(columns=["Label", "is_attack"])
    y = df["is_attack"]
    labels = df["Label"]
    X_tr, X_te, y_tr, y_te, lab_tr, lab_te = train_test_split(
        X, y, labels, test_size=0.2, stratify=labels, random_state=SEED)
    print(f"Train: {X_tr.shape}   Test: {X_te.shape}   Features: {X.shape[1]}")
    return X_tr, X_te, y_tr, y_te, lab_tr, lab_te


# ---------------------------------------------------------------- 2. tuning
def tune_random_forest(X_tr, y_tr, lab_tr):
    """Randomised search with 3-fold CV on a stratified 25% sample of the TRAINING set
    (sampling keeps the search fast; the test set is never used here)."""
    X_s, _, y_s, _ = train_test_split(X_tr, y_tr, train_size=0.25,
                                      stratify=lab_tr, random_state=SEED)
    grid = {
        "n_estimators": [100, 200],
        "max_depth": [None, 20, 30],
        "min_samples_leaf": [1, 2, 5],
        "max_features": ["sqrt", 0.3],
    }
    search = RandomizedSearchCV(
        RandomForestClassifier(class_weight="balanced", n_jobs=-1, random_state=SEED),
        grid, n_iter=10, scoring="f1",
        cv=StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED),
        random_state=SEED, n_jobs=1, verbose=0)
    t = time.time()
    search.fit(X_s, y_s)
    cv = pd.DataFrame(search.cv_results_)[["params", "mean_test_score", "std_test_score"]]
    cv = cv.sort_values("mean_test_score", ascending=False)
    cv.to_csv(RES / "rf_tuning_cv.csv", index=False)
    print(f"Searched 10 combinations x 3 folds in {time.time() - t:.0f} s")
    print(f"Best CV F1 = {search.best_score_:.4f}  with {search.best_params_}")
    return search.best_params_, search.best_score_


# ---------------------------------------------------------------- 3. models
def build_models(best_rf_params, y_tr):
    neg, pos = (y_tr == 0).sum(), (y_tr == 1).sum()
    return {
        "Dummy": DummyClassifier(strategy="most_frequent"),
        "Logistic Regression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=1000, class_weight="balanced")),
        "Random Forest": RandomForestClassifier(
            **best_rf_params, class_weight="balanced", n_jobs=-1, random_state=SEED),
        "XGBoost": XGBClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.1, tree_method="hist",
            scale_pos_weight=neg / pos, n_jobs=-1, random_state=SEED, eval_metric="logloss"),
    }


# ---------------------------------------------------------------- 4. evaluation
def evaluate(model, X, y):
    t = time.time()
    proba = model.predict_proba(X)[:, 1]
    pred_time = time.time() - t
    pred = (proba >= 0.5).astype(int)          # = model.predict(X)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    has_both = len(np.unique(y)) == 2
    return {
        "accuracy": accuracy_score(y, pred),
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "roc_auc": roc_auc_score(y, proba) if has_both else np.nan,
        "pr_auc": average_precision_score(y, proba) if has_both else np.nan,
        "TP": int(tp), "FP": int(fp), "FN": int(fn), "TN": int(tn),
        "pred_us_per_flow": pred_time / len(X) * 1e6,
    }, proba, pred


def per_attack_type(labels, y_true, pred):
    df = pd.DataFrame({"label": labels.values, "correct": pred == y_true.values})
    out = df.groupby("label")["correct"].agg(n="count", correct="sum")
    out["rate_%"] = (out["correct"] / out["n"] * 100).round(2)
    out["meaning"] = np.where(out.index == "BENIGN", "correctly allowed", "detected (recall)")
    return out


# ---------------------------------------------------------------- figures
def plot_confusion(y, pred, title, path):
    cm = confusion_matrix(y, pred, labels=[0, 1])
    pct = cm / cm.sum(axis=1, keepdims=True) * 100
    fig, ax = plt.subplots(figsize=(5, 4.3))
    ax.imshow(pct, cmap="Blues", vmin=0, vmax=100)
    ax.grid(False)
    names = ["BENIGN", "ATTACK"]
    tags = [["TN", "FP"], ["FN", "TP"]]
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{tags[i][j]}\n{cm[i, j]:,}\n({pct[i, j]:.2f}%)", ha="center",
                    va="center", fontsize=11, color="white" if pct[i, j] > 50 else "#0b0b0b")
    ax.set_xticks([0, 1], names)
    ax.set_yticks([0, 1], names)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_curves(curves, y, path):
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.3))
    for name, proba in curves.items():
        fpr, tpr, _ = roc_curve(y, proba)
        prec, rec, _ = precision_recall_curve(y, proba)
        axes[0].plot(fpr, tpr, lw=2, color=COLORS[name],
                     label=f"{name} (AUC={roc_auc_score(y, proba):.4f})")
        axes[1].plot(rec, prec, lw=2, color=COLORS[name],
                     label=f"{name} (AP={average_precision_score(y, proba):.4f})")
    # All good models hug the corner, so zoom in: log-scale FPR and the top-right of PR
    axes[0].set_xscale("log")
    axes[0].set(xlim=(1e-5, 1), ylim=(0.8, 1.005), xlabel="False Positive Rate (log scale)",
                ylabel="True Positive Rate (Recall)", title="ROC curve (zoomed) - Wednesday test")
    axes[1].set(xlim=(0.9, 1.002), ylim=(0.9, 1.002), xlabel="Recall", ylabel="Precision",
                title="Precision-Recall curve (zoomed)")
    for ax in axes:
        ax.legend(loc="lower left", fontsize=8, frameon=False)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_model_comparison(table, path):
    metrics = ["precision", "recall", "f1"]
    names = [m for m in table.index if m != "Dummy"]
    x = np.arange(len(metrics))
    w = 0.8 / len(names)
    fig, ax = plt.subplots(figsize=(8, 4))
    for i, name in enumerate(names):
        vals = table.loc[name, metrics].values.astype(float)
        bars = ax.bar(x + i * w - 0.4 + w / 2, vals, w * 0.92, color=COLORS[name], label=name)
        ax.bar_label(bars, fmt="%.4f", fontsize=7, padding=2)
    ax.set_xticks(x, ["Precision", "Recall", "F1-score"])
    ax.set_ylim(0.9, 1.005)
    ax.set_title("Model comparison on the Wednesday test set (attack class)")
    ax.legend(frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, -0.1))
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_generalisation(wed, fri, path):
    """Same models, two test sets: seen attack types (Wednesday) vs unseen DDoS (Friday)."""
    names = [m for m in wed.index if m != "Dummy"]
    x = np.arange(len(names))
    fig, ax = plt.subplots(figsize=(7.5, 4))
    b1 = ax.bar(x - 0.2, wed.loc[names, "recall"].astype(float), 0.38, color="#2a78d6",
                label="Wednesday test (DoS types seen in training)")
    b2 = ax.bar(x + 0.2, fri.loc[names, "recall"].astype(float), 0.38, color="#eb6834",
                label="Friday DDoS (attack type never seen)")
    ax.bar_label(b1, fmt="%.3f", fontsize=8, padding=2)
    ax.bar_label(b2, fmt="%.3f", fontsize=8, padding=2)
    ax.set_xticks(x, names)
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("Recall (attacks detected)")
    ax.set_title("Generalisation gap: detection rate on seen vs unseen attacks")
    ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.1), ncol=2)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_feature_importance(model, features, path, top=20):
    imp = pd.Series(model.feature_importances_, index=features).sort_values().tail(top)
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.barh(imp.index, imp.values, color="#1baf7a", height=0.7)
    ax.set_xlabel("Mean decrease in impurity (Gini importance)")
    ax.set_title(f"Random Forest - top {top} features")
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return imp.sort_values(ascending=False)


def plot_error_confidence(proba, y, path):
    """Where do the errors sit on the probability scale? (near 0.5 = uncertain)."""
    pred = (proba >= 0.5).astype(int)
    fn = proba[(y == 1) & (pred == 0)]
    fp = proba[(y == 0) & (pred == 1)]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.6), sharey=False)
    bins = np.linspace(0, 1, 21)
    axes[0].hist(fn, bins=bins, color="#e34948", edgecolor="white")
    axes[0].set(title=f"Missed attacks (FN, n={len(fn)})", xlabel="Predicted attack probability",
                ylabel="Flows")
    axes[1].hist(fp, bins=bins, color="#eda100", edgecolor="white")
    axes[1].set(title=f"False alarms (FP, n={len(fp)})", xlabel="Predicted attack probability")
    for ax in axes:
        ax.axvline(0.5, ls="--", color="#52514e", lw=1)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


# ---------------------------------------------------------------- 6. error analysis
def error_analysis(X_te, y_te, lab_te, proba, pred, top_features):
    banner("ERROR ANALYSIS - Random Forest on Wednesday test set")
    df = X_te.copy()
    df["Label"] = lab_te.values
    df["y_true"] = y_te.values
    df["y_pred"] = pred
    df["p_attack"] = proba
    df["outcome"] = np.select(
        [(df.y_true == 1) & (df.y_pred == 1), (df.y_true == 0) & (df.y_pred == 0),
         (df.y_true == 1) & (df.y_pred == 0)], ["TP", "TN", "FN"], "FP")

    errors = df[df.outcome.isin(["FN", "FP"])]
    print("Errors by true label:")
    print(errors.groupby(["outcome", "Label"]).size().to_string())

    # Compare typical (median) values of errors vs correctly classified flows
    cols = list(top_features.index[:6])
    profile = df.groupby("outcome")[cols].median().round(1)
    print("\nMedian of top features per outcome (are errors 'look-alikes'?):")
    print(profile.to_string())
    profile.to_csv(RES / "error_profile.csv")

    print(f"\nMean model confidence -> FN: {df[df.outcome=='FN'].p_attack.mean():.3f}"
          f" | FP: {df[df.outcome=='FP'].p_attack.mean():.3f}"
          f" | TP: {df[df.outcome=='TP'].p_attack.mean():.3f}")
    errors.sort_values("p_attack").to_csv(RES / "misclassified_flows.csv", index=False)
    print(f"Saved {len(errors)} misclassified flows -> results/misclassified_flows.csv")


# ---------------------------------------------------------------- main
def main():
    for d in (MODELS, RES, FIG):
        d.mkdir(parents=True, exist_ok=True)

    banner("1. LOAD & SPLIT (Wednesday, 80/20 stratified by attack type)")
    X_tr, X_te, y_tr, y_te, lab_tr, lab_te = load_split()
    features = list(X_tr.columns)

    banner("2. TUNE RANDOM FOREST (3-fold CV on training data only)")
    best_params, best_cv = tune_random_forest(X_tr, y_tr, lab_tr)

    banner("3-4. TRAIN & EVALUATE ON UNSEEN TEST SET")
    models = build_models(best_params, y_tr)
    rows, curves, preds = {}, {}, {}
    for name, model in models.items():
        t = time.time()
        model.fit(X_tr, y_tr)
        train_time = time.time() - t
        metrics, proba, pred = evaluate(model, X_te, y_te)
        metrics["train_s"] = train_time
        rows[name], preds[name] = metrics, pred
        if name != "Dummy":
            curves[name] = proba
        print(f"{name:<20} F1={metrics['f1']:.4f}  P={metrics['precision']:.4f}  "
              f"R={metrics['recall']:.4f}  FPR={metrics['fpr']:.4f}  train={train_time:.1f}s")

    table = pd.DataFrame(rows).T
    table.index.name = "model"
    table.to_csv(RES / "metrics_wednesday_test.csv")
    print("\n" + table[["accuracy", "precision", "recall", "f1", "fpr", "roc_auc",
                        "pr_auc", "FP", "FN", "train_s"]].round(4).to_string())

    rf = models["Random Forest"]
    rf_proba = curves["Random Forest"]
    rf_pred = preds["Random Forest"]

    print("\nDetection rate per attack type:")
    per_type = {name: per_attack_type(lab_te, y_te, preds[name])["rate_%"]
                for name in models if name != "Dummy"}
    per_type = pd.DataFrame(per_type)
    per_type.insert(0, "n_test", lab_te.value_counts())
    print(per_type.to_string())
    per_type.to_csv(RES / "per_attack_type_wednesday.csv")

    banner("5. GENERALISATION TEST - Friday DDoS (different day, attack never seen)")
    fri = pd.read_parquet(PROC / "friday_clean.parquet")
    X_f, y_f, lab_f = fri[features], fri["is_attack"], fri["Label"]
    print(fri["Label"].value_counts().to_string())
    fri_rows = {}
    for name, model in models.items():
        m, _, pred_f = evaluate(model, X_f, y_f)
        fri_rows[name] = m
        if name == "Random Forest":
            plot_confusion(y_f, pred_f, "Random Forest - Friday DDoS (unseen)",
                           FIG / "cm_rf_friday.png")
    fri_table = pd.DataFrame(fri_rows).T
    fri_table.index.name = "model"
    fri_table.to_csv(RES / "metrics_friday_ddos.csv")
    print("\n" + fri_table[["accuracy", "precision", "recall", "f1", "fpr", "roc_auc",
                            "FP", "FN"]].round(4).to_string())

    banner("6. FIGURES & FEATURE IMPORTANCE")
    plot_confusion(y_te, rf_pred, "Random Forest - Wednesday test set",
                   FIG / "cm_rf_wednesday.png")
    plot_confusion(y_te, preds["Logistic Regression"], "Logistic Regression - Wednesday test",
                   FIG / "cm_logreg_wednesday.png")
    plot_curves(curves, y_te, FIG / "roc_pr_curves.png")
    plot_model_comparison(table, FIG / "model_comparison.png")
    plot_generalisation(table, fri_table, FIG / "generalisation_gap.png")
    top_feats = plot_feature_importance(rf, features, FIG / "feature_importance.png")
    plot_error_confidence(rf_proba, y_te.values, FIG / "error_confidence.png")
    top_feats.to_csv(RES / "feature_importance_top20.csv", header=["importance"])
    print("Top 10 features:\n" + top_feats.head(10).round(4).to_string())

    error_analysis(X_te, y_te, lab_te, rf_proba, rf_pred, top_feats)

    banner("7. SAVE MODEL")
    joblib.dump(rf, MODELS / "rf_dos_detector.joblib", compress=3)
    joblib.dump(models["XGBoost"], MODELS / "xgb_dos_detector.joblib", compress=3)
    card = {
        "model": "RandomForestClassifier",
        "task": "Binary DoS detection on CIC-IDS2017 network flows (0=BENIGN, 1=ATTACK)",
        "trained_on": "Wednesday-workingHours (80% stratified split, seed 42)",
        "created": datetime.now().isoformat(timespec="seconds"),
        "hyperparameters": {**best_params, "class_weight": "balanced"},
        "cv_f1_tuning": round(best_cv, 4),
        "features": features,
        "decision_threshold": 0.5,
        "test_metrics_wednesday": {k: round(float(v), 4) for k, v in rows["Random Forest"].items()},
        "test_metrics_friday_ddos": {k: round(float(v), 4) for k, v in fri_rows["Random Forest"].items()},
        "versions": {"scikit-learn": sklearn.__version__, "xgboost": xgboost.__version__,
                     "pandas": pd.__version__, "numpy": np.__version__},
    }
    (MODELS / "model_card.json").write_text(json.dumps(card, indent=2))

    # Keep the unseen test flows for the mitigation demo
    test_df = X_te.copy()
    test_df["Label"] = lab_te.values
    test_df["is_attack"] = y_te.values
    test_df.to_parquet(PROC / "wednesday_test.parquet", index=False)

    size = (MODELS / "rf_dos_detector.joblib").stat().st_size / 1e6
    print(f"Saved models/rf_dos_detector.joblib ({size:.1f} MB), models/model_card.json")
    print("Done.")


if __name__ == "__main__":
    main()
