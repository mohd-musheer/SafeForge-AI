from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import joblib
from pathlib import Path

from predict_flows import (
    get_expected_features,
    prepare_inference_frame,
    resolve_model_path
)

app = FastAPI(title="SafeForge AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

BASE_DIR = Path(__file__).resolve().parent
INDEX_PATH = BASE_DIR / "index.html"
TRAFFIC_SAMPLE_PATH = BASE_DIR / "traffic.csv"
PREDICTIONS_PATH = BASE_DIR / "predictions.csv"

MODEL_PATH = resolve_model_path("safeforge_model.pkl")
model = joblib.load(MODEL_PATH)

@app.get("/", response_class=HTMLResponse)
def home():
    with INDEX_PATH.open("r", encoding="utf-8") as f:
        return f.read()


@app.get("/traffic.csv")
async def download_sample_traffic():
    return FileResponse(
        path=TRAFFIC_SAMPLE_PATH,
        filename="traffic.csv",
        media_type="text/csv"
    )


@app.get("/download")
async def download_predictions():
    return FileResponse(
        path=PREDICTIONS_PATH,
        filename="predictions.csv",
        media_type="text/csv"
    )


@app.post("/predict")
async def predict(file: UploadFile = File(...)):

    try:

        raw_df = pd.read_csv(file.file)

        # Validate that we have data
        if raw_df.empty or len(raw_df) == 0:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "message": "CSV file is empty. Please upload a file with at least 1 row of data."
                }
            )

        expected_features = get_expected_features(model)

        inference_df, missing_columns, derived_columns = prepare_inference_frame(
            raw_df,
            expected_features
        )

        # Validate inference dataframe has samples
        if len(inference_df) == 0:
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "message": "No valid data rows found after processing. Check CSV format."
                }
            )

        predictions = model.predict(inference_df)

        # attach predictions
        result_df = raw_df.copy()
        result_df["Predicted Label"] = predictions

        # save result file
        output_path = PREDICTIONS_PATH
        result_df.to_csv(output_path, index=False)

        # summary stats
        label_counts = result_df["Predicted Label"].value_counts().to_dict()

        total_flows = len(result_df)
        attack_flows = total_flows - label_counts.get("BENIGN", 0)

        attack_ratio = 0
        if total_flows > 0:
            attack_ratio = round((attack_flows / total_flows) * 100, 2)

        if attack_ratio == 0:
            risk_level = "LOW"
        elif attack_ratio < 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        response = {

            "summary": {
                "total_flows": total_flows,
                "attack_flows": attack_flows,
                "benign_flows": label_counts.get("BENIGN", 0),
                "attack_ratio_percent": attack_ratio,
                "risk_level": risk_level
            },

            "prediction_distribution": label_counts,

            "feature_diagnostics": {
                "missing_columns_filled_with_zero": missing_columns,
                "derived_columns": derived_columns,
                "expected_feature_count": len(expected_features)
            },

            "files": {
                "prediction_csv_saved_as": output_path.name
            },

            "status": "success"
        }

        return JSONResponse(content=response)

    except Exception as e:

        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": str(e)
            }
        )
