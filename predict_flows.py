import argparse
from pathlib import Path

import joblib
import pandas as pd


RENAME_MAP = {
    "Dst Port": "Destination Port",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Fwd Pkt Len Max": "Fwd Packet Length Max",
    "Fwd Pkt Len Min": "Fwd Packet Length Min",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Pkt Len Std": "Fwd Packet Length Std",
    "Bwd Pkt Len Max": "Bwd Packet Length Max",
    "Bwd Pkt Len Min": "Bwd Packet Length Min",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Pkt Len Std": "Bwd Packet Length Std",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Fwd IAT Tot": "Fwd IAT Total",
    "Bwd IAT Tot": "Bwd IAT Total",
    "Fwd Header Len": "Fwd Header Length",
    "Bwd Header Len": "Bwd Header Length",
    "Fwd Pkts/s": "Fwd Packets/s",
    "Bwd Pkts/s": "Bwd Packets/s",
    "Pkt Len Min": "Min Packet Length",
    "Pkt Len Max": "Max Packet Length",
    "Pkt Len Mean": "Packet Length Mean",
    "Pkt Len Std": "Packet Length Std",
    "Pkt Len Var": "Packet Length Variance",
    "FIN Flag Cnt": "FIN Flag Count",
    "SYN Flag Cnt": "SYN Flag Count",
    "RST Flag Cnt": "RST Flag Count",
    "PSH Flag Cnt": "PSH Flag Count",
    "ACK Flag Cnt": "ACK Flag Count",
    "URG Flag Cnt": "URG Flag Count",
    "ECE Flag Cnt": "ECE Flag Count",
    "Pkt Size Avg": "Average Packet Size",
    "Fwd Seg Size Avg": "Avg Fwd Segment Size",
    "Bwd Seg Size Avg": "Avg Bwd Segment Size",
    "Fwd Byts/b Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Pkts/b Avg": "Fwd Avg Packets/Bulk",
    "Fwd Blk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Byts/b Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Pkts/b Avg": "Bwd Avg Packets/Bulk",
    "Bwd Blk Rate Avg": "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts": "Subflow Fwd Packets",
    "Subflow Fwd Byts": "Subflow Fwd Bytes",
    "Subflow Bwd Pkts": "Subflow Bwd Packets",
    "Subflow Bwd Byts": "Subflow Bwd Bytes",
    "Init Fwd Win Byts": "Init_Win_bytes_forward",
    "Init Bwd Win Byts": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
}

DROP_COLUMNS = [
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Protocol",
    "Timestamp",
    "Label",
]

FALLBACK_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run inference on CICFlowMeter CSV data using a saved sklearn model."
    )
    parser.add_argument(
        "input_csv",
        nargs="?",
        default="traffic.csv",
        help="Path to the CICFlowMeter CSV file.",
    )
    parser.add_argument(
        "--model",
        default="model.pkl",
        help="Path to the saved sklearn model (.pkl). Default: model.pkl",
    )
    parser.add_argument(
        "--output",
        default="predictions.csv",
        help="Path to the output CSV file. Default: predictions.csv",
    )
    return parser.parse_args()


def resolve_model_path(model_path):
    model_file = Path(model_path)
    if model_file.exists():
        return model_file

    fallback = Path("safeforge_model.pkl")
    if model_file.name == "model.pkl" and fallback.exists():
        print("model.pkl not found; using safeforge_model.pkl instead.")
        return fallback

    raise FileNotFoundError(f"Model file not found: {model_file}")


def get_expected_features(model):
    if hasattr(model, "feature_names_in_") and len(model.feature_names_in_) > 0:
        expected = [str(name) for name in model.feature_names_in_]
        print(f"Using schema from model.feature_names_in_ ({len(expected)} features).")
        return expected

    print(
        "Model does not expose feature_names_in_; using fallback 78-feature training schema."
    )
    return FALLBACK_FEATURES


def prepare_inference_frame(raw_df, expected_features):
    df = raw_df.copy()
    df.columns = df.columns.str.strip()
    df = df.rename(columns=RENAME_MAP)
    df = df.drop(columns=[col for col in DROP_COLUMNS if col in df.columns], errors="ignore")

    inference_df = pd.DataFrame(index=df.index)
    missing_columns = []
    derived_columns = []

    for expected_name in expected_features:
        stripped_name = expected_name.strip()

        if stripped_name in df.columns:
            inference_df[expected_name] = df[stripped_name]
            continue

        if expected_name in df.columns:
            inference_df[expected_name] = df[expected_name]
            continue

        if stripped_name.endswith(".1"):
            base_name = stripped_name.rsplit(".", 1)[0]
            if base_name in df.columns:
                inference_df[expected_name] = df[base_name]
                derived_columns.append(f"{stripped_name} <- {base_name}")
                continue

        missing_columns.append(stripped_name)
        inference_df[expected_name] = 0

    inference_df = inference_df.apply(pd.to_numeric, errors="coerce")
    inference_df = inference_df.replace([float("inf"), float("-inf")], 0).fillna(0)

    return inference_df, missing_columns, derived_columns


def main():
    args = parse_args()

    model_path = resolve_model_path(args.model)
    model = joblib.load(model_path)
    expected_features = get_expected_features(model)

    input_df = pd.read_csv(args.input_csv)
    print(f"Loaded {len(input_df)} rows from {args.input_csv}")

    inference_df, missing_columns, derived_columns = prepare_inference_frame(
        input_df, expected_features
    )

    if len(expected_features) != 78:
        print(f"Warning: model expects {len(expected_features)} features, not 78.")

    print(f"Prepared inference dataframe with shape: {inference_df.shape}")

    if derived_columns:
        print("Derived columns:")
        for item in derived_columns:
            print(f"  - {item}")

    if missing_columns:
        print("Missing columns filled with 0:")
        for col in missing_columns:
            print(f"  - {col}")
    else:
        print("No training-feature columns are missing.")

    predictions = model.predict(inference_df)

    output_df = inference_df.copy()
    output_df["Predicted Label"] = predictions
    output_df.to_csv(args.output, index=False)

    print(f"Saved predictions to {args.output}")


if __name__ == "__main__":
    main()
