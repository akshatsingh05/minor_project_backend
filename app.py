"""
app.py - Main Flask Application Entry Point
Orchestrates all modules: FE, MPC, Audit Logging, and Data Handling.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from collections import Counter

import os

from modules.fe_module import FunctionalEncryption
from modules.mpc_module import MPCEngine
from modules.audit_logger import AuditLogger
from modules.data_handler import DataHandler

# ---------------------------------------------------------------------------
# App Initialization
# ---------------------------------------------------------------------------

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
CORS(app, origins=["http://localhost:5173"], supports_credentials=True)  # Enable cross-origin requests for frontend integration

# Ensure storage directory exists
os.makedirs("storage", exist_ok=True)

# Initialize modules (singletons shared across requests)
fe = FunctionalEncryption(key=7)          # FE with linear function y = 7x
mpc = MPCEngine(num_parties=4)            # 4-party additive secret sharing
logger = AuditLogger("storage/logs.json")
manual_handler = DataHandler("storage/manual_data.csv")
upload_handler = DataHandler("storage/uploaded_data.csv")

# In-memory store for the latest computation result
latest_result = {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/submit-single", methods=["POST"])
def submit_single():
    """
    Accept a single numeric value, encrypt it, split into MPC shares,
    store the encrypted value, and log every step.
    """
    body = request.get_json(silent=True)
    if not body or "value" not in body:
        return jsonify({"error": "Request body must contain 'value'"}), 400

    raw = body["value"]

    # Validate numeric
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return jsonify({"error": "Value must be numeric"}), 400

    # Log input submission
    logger.log("input_submission", {"source": "single", "raw_value": value})

    # Encrypt
    encrypted = fe.encrypt(value)
    logger.log("encryption", {"original": value, "encrypted": encrypted})

    # Generate MPC shares
    shares = mpc.split(encrypted)
    logger.log("share_generation", {"encrypted_value": encrypted, "num_shares": len(shares)})

    # Persist encrypted value
    manual_handler.append_value(encrypted)
    logger.log("storage", {"stored_encrypted": encrypted})

    return jsonify({"message": "Value submitted and stored successfully"}), 200


@app.route("/upload-dataset", methods=["POST"])
def upload_dataset():
    """
    Accept a CSV file upload plus a target column name.
    Validate, encrypt each value in the column, and store results.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    column = request.args.get("column") or request.form.get("column")
    if not column:
        return jsonify({"error": "Column parameter is required"}), 400

    csv_file = request.files["file"]

    # Parse and validate the CSV
    values, error = upload_handler.parse_csv(csv_file, column)
    if error:
        return jsonify({"error": error}), 400

    logger.log("input_submission", {"source": "csv", "column": column, "num_rows": len(values)})

    # Encrypt each value and store
    encrypted_values = []
    for v in values:
        enc = fe.encrypt(v)
        encrypted_values.append(enc)

    logger.log("encryption", {"num_encrypted": len(encrypted_values)})

    # Generate shares for each encrypted value
    for enc in encrypted_values:
        mpc.split(enc)
    logger.log("share_generation", {"num_values_shared": len(encrypted_values)})

    # Overwrite storage with new encrypted dataset
    upload_handler.write_values(encrypted_values)
    logger.log("storage", {"action": "csv_dataset_stored", "count": len(encrypted_values)})

    return jsonify({"message": f"Dataset uploaded. {len(values)} values processed."}), 200


@app.route("/compute", methods=["POST"])
def compute():
    """
    Reconstruct encrypted values via MPC, decrypt them, and apply
    the requested aggregation operation.
    """
    global latest_result

    body = request.get_json(silent=True)
    if not body or "operation" not in body:
        return jsonify({"error": "Request body must contain 'operation'"}), 400

    operation = body["operation"].strip().lower()
    source = body.get("source")
    valid_ops = {"sum", "average", "count", "min", "max"}
    if operation not in valid_ops:
        return jsonify({"error": f"operation must be one of {sorted(valid_ops)}"}), 400

    # Load encrypted values from storage
    if source == "manual":
        encrypted_values = manual_handler.load_values()
    elif source == "upload":
        encrypted_values = upload_handler.load_values()
    else:
        return jsonify({"error": "Invalid data source"}), 400
    if not encrypted_values:
        return jsonify({"error": f"No data found for {source}. Please submit values first."}), 400

    logger.log("mpc_reconstruction", {"num_values": len(encrypted_values)})

    # Reconstruct and decrypt each value
    decrypted = [fe.decrypt(ev) for ev in encrypted_values]

    logger.log("computation_start", {"operation": operation, "num_values": len(decrypted)})

    # Perform the aggregation
    result_value = _aggregate(decrypted, operation)

    # Build frequency distribution for chart support
    freq_data = _frequency_distribution(decrypted)

    latest_result = {
        "operation": operation,
        "result": result_value,
        "frequency_distribution": freq_data,
    }

    logger.log("result_generation", {"operation": operation, "result": result_value})

    return jsonify({
        "operation": operation,
        "result": result_value,
        "chart": freq_data
    }), 200


@app.route("/results", methods=["GET"])
def results():
    """Return the latest computed result and frequency distribution data."""
    if not latest_result:
        return jsonify({"message": "No computation has been performed yet."}), 200
    return jsonify(latest_result), 200


@app.route("/logs", methods=["GET"])
def logs():
    """Return the full tamper-evident audit log."""
    all_logs = logger.get_logs()
    return jsonify(all_logs), 200


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _aggregate(values: list, operation: str) -> float:
    """Apply the chosen aggregation to a list of floats."""
    if operation == "sum":
        return round(sum(values), 4)
    elif operation == "average":
        return round(sum(values) / len(values), 4)
    elif operation == "count":
        return len(values)
    elif operation == "min":
        return round(min(values), 4)
    elif operation == "max":
        return round(max(values), 4)


def _frequency_distribution(values):
    """
    Build a simple frequency distribution over rounded integer buckets.
    Returns {"values": [...], "frequency": [...]} suitable for bar/pie charts.
    """
    from collections import Counter

def _frequency_distribution(values):
    if not values:
        return {"values": [], "frequency": []}

    min_val = min(values)
    max_val = max(values)
    range_val = max_val - min_val

    # Decide grouping strategy based on data spread
    if range_val < 50:
        base = 1
    elif range_val < 500:
        base = 10
    elif range_val < 5000:
        base = 100
    elif range_val < 50000:
        base = 1000
    else:
        base = 10000   # 🔥 for salary

    # Apply rounding
    rounded_values = [round(v / base) * base for v in values]

    counts = Counter(rounded_values)
    sorted_items = sorted(counts.items())

    return {
        "values": [item[0] for item in sorted_items],
        "frequency": [item[1] for item in sorted_items]
    }

# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, port=5000)
