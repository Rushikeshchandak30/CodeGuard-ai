# ⚠️ TEST FILE — CodeGuard AI v8.0 ML Model File Scanner
# Every pattern below should trigger a CG_MODEL_* finding.
# Open in Windsurf with CodeGuard installed — expect 10+ diagnostics.

import pickle
import yaml
import joblib

# ── Unsafe pickle.load (CG_MODEL_001) ────────────────────────────────────────
with open("model.pkl", "rb") as f:
    model = pickle.load(f)               # CRITICAL: arbitrary code execution

# ── Unsafe pickle.loads on user-controlled data (CG_MODEL_002) ───────────────
def deserialize_user_data(raw_bytes: bytes):
    return pickle.loads(raw_bytes)       # CRITICAL: never deserialize untrusted input

# ── Unsafe torch.load without weights_only (CG_MODEL_003) ────────────────────
import torch

weights = torch.load("model.pt")                        # HIGH: missing weights_only=True
weights_v2 = torch.load("checkpoint.pt", map_location="cpu")  # HIGH: still missing weights_only

# Safe alternative (should NOT trigger):
# safe_weights = torch.load("model.pt", weights_only=True)

# ── Unsafe joblib.load (CG_MODEL_004) ────────────────────────────────────────
pipeline = joblib.load("sklearn_model.pkl")              # HIGH: pickle-backed, can exec code

# ── Unsafe yaml.load without SafeLoader (CG_MODEL_005) ───────────────────────
with open("config.yaml") as f:
    config = yaml.load(f)                                # CRITICAL: use yaml.safe_load

with open("model_config.yaml") as f:
    params = yaml.load(f, Loader=yaml.Loader)            # CRITICAL: FullLoader still unsafe

# Safe alternative (should NOT trigger):
# safe_config = yaml.safe_load(f)

# ── trust_remote_code=True (CG_MODEL_006) ────────────────────────────────────
from transformers import AutoModelForCausalLM, AutoTokenizer

model = AutoModelForCausalLM.from_pretrained(
    "some-org/some-model",
    trust_remote_code=True              # CRITICAL: executes arbitrary repo Python
)
tokenizer = AutoTokenizer.from_pretrained(
    "some-org/some-tokenizer",
    trust_remote_code=True              # CRITICAL
)

# ── Keras load_model without safe_mode (CG_MODEL_007) ────────────────────────
from tensorflow import keras

keras_model = keras.models.load_model("model.h5")              # HIGH: Lambda layers can exec
keras_model2 = keras.models.load_model("model.keras")          # HIGH

# Safe alternative (should NOT trigger):
# keras.models.load_model("model.h5", safe_mode=True)

# ── HuggingFace config with auto_map (forces trust_remote_code) ──────────────
# The scanner also checks config.json files for "auto_map" keys.
# See: test-samples/v8-model-configs/config.json

# ── Summary of what the byte-level scanner would catch ───────────────────────
# For actual .pkl/.pt files, run:
#   Ctrl+Shift+P → "CodeGuard v8: Scan ML Model Files"
#
# To create a test pickle with os.system:
#   python -c "import pickle; pickle.dump(__import__('os').system, open('bad.pkl','wb'))"
#
# To create a test pickle with subprocess.Popen:
#   python -c "import pickle,subprocess; pickle.dump(subprocess.Popen, open('evil.pkl','wb'))"
