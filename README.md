# SafeForge AI

SafeForge AI is a lightweight network threat detection web app that analyzes flow-based CSV traffic data and predicts whether traffic is benign or suspicious using a trained scikit-learn model.


live : ..

docker image : https://hub.docker.com/r/mohdmusheer/safeforge-ai

It combines:

- a FastAPI backend for inference
- a browser-based frontend for uploads and result visualization
- a reusable Python inference pipeline for CSV preprocessing and prediction
- a pre-trained model file for quick local deployment

The current workflow is built for CICFlowMeter-style CSV exports, not raw PCAP ingestion yet.

## Why SafeForge AI

Security teams and learners often have packet captures or flow exports but no simple interface to run quick ML-based screening. SafeForge AI aims to make that step easier:

- upload a network traffic CSV
- run inference through a trained model
- review attack ratio, flow counts, and class distribution
- download a prediction-enriched CSV for further investigation

## Current Features

- CSV-based network traffic analysis from the browser
- FastAPI inference endpoint for backend integration
- Automatic preprocessing to align incoming CSV columns with the trained model schema
- Graceful handling of missing columns by filling missing model features with `0`
- Basic derived-column support for schema variants such as `.1` suffixes
- Summary metrics:
  - total flows
  - benign flows
  - attack flows
  - attack ratio
  - overall risk level
- Interactive distribution chart in the UI
- Downloadable `predictions.csv`
- Built-in demo loader using the included `traffic.csv`
- Docker support for quick deployment

## How It Works

1. A user uploads a CSV from the web interface.
2. The backend reads the file with pandas.
3. The preprocessing pipeline:
   - trims column names
   - renames alternate CICFlowMeter-style columns into the model schema
   - removes metadata columns like IPs, ports, timestamps, and labels when needed
   - fills missing expected features with `0`
   - converts values to numeric form
   - replaces `NaN`, `inf`, and `-inf`
4. The trained model predicts a label for each row.
5. The backend returns summary metrics and saves `predictions.csv`.
6. The frontend renders charts and exposes a download link.

## Tech Stack

- Backend: FastAPI
- Frontend: HTML, Tailwind CSS, Chart.js
- ML / Data: pandas, scikit-learn, joblib
- Deployment: Uvicorn, Docker

## Repository Structure

```text
SafeForge-AI/
|-- api.py                  # FastAPI app and inference endpoints
|-- predict_flows.py        # Reusable preprocessing + CLI inference script
|-- index.html              # Frontend UI
|-- requirements.txt        # Python dependencies
|-- dockerfile              # Container image definition
|-- safeforge_model.pkl     # Trained model used for inference
|-- traffic.csv             # Demo input file used by the UI
|-- predictions.csv         # Generated output file after inference
|-- Dataset/                # Dataset notes and expected training data location
|-- model_train/            # Training and experimentation notebooks
|-- predict.ipynb           # Notebook-based prediction workflow
`-- LICENSE                 # MIT License
```

## Input Data Format

SafeForge AI expects a CSV generated from network flow analysis tools such as CICFlowMeter, or another CSV with equivalent statistical flow features.

The pipeline supports common CICFlowMeter naming variants by mapping alternate names to the expected schema. Example feature families include:

- flow duration and port information
- forward and backward packet counts
- packet length statistics
- traffic-rate features
- inter-arrival timing features
- TCP flag counts
- active and idle time statistics

Important notes:

- raw `.pcap` files are not accepted directly yet
- input rows should represent network flows, not raw packets
- non-numeric feature values are coerced and sanitized during preprocessing

## Risk Levels

The current backend assigns risk based on the percentage of non-benign predictions:

- `LOW`: `0%` attack flows
- `MEDIUM`: less than `10%` attack flows
- `HIGH`: `10%` attack flows or more

This is a simple operational heuristic for UI summarization, not a full SOC scoring model.

## Local Setup

### 1. Clone the repository

```bash
git clone https://github.com/mohd-musheer/SafeForge-AI.git
cd SafeForge-AI
```

### 2. Create and activate a virtual environment

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Linux / macOS:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
uvicorn api:app --reload
```

Open:

```text
http://127.0.0.1:8000
```

## Docker Usage

Build the image:

```bash
docker build -t safeforge-ai .
```

Run the container:

```bash
docker run -p 8000:8000 safeforge-ai
```

Open:

```text
http://127.0.0.1:8000
```

## Web App Usage

1. Start the FastAPI server.
2. Open the home page in your browser.
3. Either:
   - upload your own CSV file, or
   - click `Load Demo` to load the included `traffic.csv`
4. Click `Analyze Traffic`.
5. Review:
   - total flows
   - benign vs attack counts
   - attack ratio
   - model diagnostics
   - prediction distribution chart
6. Download the generated `predictions.csv`.

## Command-Line Inference

The repository also includes a standalone CLI workflow in `predict_flows.py`.

Run with defaults:

```bash
python predict_flows.py
```

Run with custom input, model, and output:

```bash
python predict_flows.py your_input.csv --model safeforge_model.pkl --output predictions.csv
```

What the script does:

- loads the model
- determines expected features from `model.feature_names_in_` when available
- falls back to a built-in 78-feature schema if needed
- preprocesses the input CSV
- predicts a label for each row
- writes the output CSV

## API Endpoints

### `GET /`

Serves the web interface.

### `GET /traffic.csv`

Returns the bundled demo CSV file.

### `POST /predict`

Accepts a CSV upload and returns JSON prediction results.

Request:

- form-data field: `file`

Successful response includes:

- `summary`
- `prediction_distribution`
- `feature_diagnostics`
- `files`
- `status`

### `GET /download`

Downloads the latest generated `predictions.csv`.

## Sample Response Shape

```json
{
  "summary": {
    "total_flows": 100,
    "attack_flows": 12,
    "benign_flows": 88,
    "attack_ratio_percent": 12.0,
    "risk_level": "HIGH"
  },
  "prediction_distribution": {
    "BENIGN": 88,
    "DDoS": 7,
    "PortScan": 5
  },
  "feature_diagnostics": {
    "missing_columns_filled_with_zero": [],
    "derived_columns": [],
    "expected_feature_count": 78
  },
  "files": {
    "prediction_csv_saved_as": "predictions.csv"
  },
  "status": "success"
}
```

## Dataset Notes

This project is associated with the CIC-IDS2017-style intrusion detection workflow. The repository already includes guidance in [Dataset/README.md](./Dataset/README.md) for obtaining the dataset used during experimentation and training preparation.

Because the full dataset is large, it is not committed to the repository.

## Model and Preprocessing Notes

- The app loads `safeforge_model.pkl` at startup.
- If a model exposes `feature_names_in_`, that schema is used automatically.
- If not, the app falls back to an internal 78-feature schema.
- Alternate feature names are normalized through a rename map.
- Missing expected model features are filled with `0`.
- Input values are converted to numeric form before prediction.

## Known Limitations

- No native PCAP upload yet
- No streaming or real-time packet capture support
- Predictions depend on the quality and compatibility of the input CSV schema
- Current risk scoring is heuristic and intentionally simple
- The app currently saves output to a single `predictions.csv`, so concurrent multi-user production usage would need a safer storage strategy
- The repository does not yet include a full automated test suite

## Future Work

Planned improvements for upcoming versions:

- native PCAP to CSV conversion inside the app
- drag-and-drop PCAP upload support
- real-time traffic monitoring and live inference
- model confidence scores and richer explanations
- attack trend dashboard and historical session storage
- support for batch jobs and multiple uploaded files
- safer multi-user output handling with per-session files
- background task processing for large uploads
- better error reporting and input validation
- role-based authentication for hosted deployments
- CI/CD pipelines and automated tests
- retraining pipeline improvements and reproducible model versioning
- model benchmarking across multiple algorithms
- exportable PDF or JSON security reports
- dark/light theme switching and richer accessibility support
- cloud deployment templates for Azure, AWS, and GCP

## Contribution Ideas

Useful areas for contribution:

- frontend polish and UX improvements
- backend validation and error handling
- model evaluation and retraining
- dataset preparation tooling
- Docker and deployment improvements
- automated tests and GitHub Actions
- explainability and analyst-friendly outputs

## Troubleshooting

### `python-multipart` error

If FastAPI reports that form-data support is missing, install dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

### Model file not found

Make sure `safeforge_model.pkl` exists in the project root, or update the model path if you are using a different file.

### Demo CSV does not load

Run the web app through FastAPI and open it via `http://127.0.0.1:8000`. The demo loader expects the backend route `/traffic.csv`, not a direct `file://` browser open.

### CSV produces poor predictions

Verify that the input was generated from a CICFlowMeter-style flow export and that the columns are close to the training schema expected by the model.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE) for details.

## Author

Built by [Mohd Musheer](https://github.com/mohd-musheer).
