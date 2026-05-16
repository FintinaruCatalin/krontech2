import math
import logging
from pathlib import Path
from typing import Any


MODEL_PATH = Path(__file__).resolve().parent / "models" / "tfidf_linear_svm_pipeline.joblib"
FALLBACK_MODEL_PATH = Path(__file__).resolve().parent / "models" / "tfidf_linear_svm.joblib"

_pipeline: Any | None = None
_pipeline_loaded = False
_loaded_model_path: Path | None = None

logger = logging.getLogger(__name__)


def _debug(message: str) -> None:
    logger.info(message)
    print(message)


def _unavailable_result() -> dict:
    return {
        "available": False,
        "label": None,
        "confidence": 0,
        "reason": "Local ML model unavailable",
    }


def _load_pipeline() -> Any | None:
    global _pipeline, _pipeline_loaded, _loaded_model_path

    # The model is loaded lazily and cached globally, so normal requests reuse
    # the same TF-IDF + SVM pipeline instead of reading the joblib file again.
    if _pipeline_loaded:
        return _pipeline

    _pipeline_loaded = True

    try:
        import joblib

        model_path = MODEL_PATH if MODEL_PATH.exists() else FALLBACK_MODEL_PATH

        if not model_path.exists():
            _debug(f"[Local ML] Model unavailable. Checked: {MODEL_PATH} and {FALLBACK_MODEL_PATH}")
            return None

        _pipeline = joblib.load(model_path)
        _loaded_model_path = model_path
        _debug(
            "[Local ML] Model loaded successfully from "
            f"{model_path}. predict={hasattr(_pipeline, 'predict')}, "
            f"predict_proba={hasattr(_pipeline, 'predict_proba')}, "
            f"decision_function={hasattr(_pipeline, 'decision_function')}"
        )
        return _pipeline
    except Exception as error:
        # Fallback behavior: local ML is optional. If the file or dependency is
        # unavailable, SMS analysis continues with the existing rule-based logic.
        _pipeline = None
        _debug(f"[Local ML] Model loading error: {error}")
        return None


def _normalize_label(raw_label: Any) -> str:
    label_text = str(raw_label).strip().lower()

    if label_text in {"phishing", "phish", "smishing", "spam", "scam", "malicious", "dangerous", "1", "true"}:
        return "phishing"

    return "safe"


def _get_class_index(pipeline: Any, raw_label: Any) -> int | None:
    classes = getattr(pipeline, "classes_", None)

    if classes is None and hasattr(pipeline, "named_steps"):
        final_step = list(pipeline.named_steps.values())[-1]
        classes = getattr(final_step, "classes_", None)

    if classes is None:
        return None

    for index, class_label in enumerate(classes):
        if class_label == raw_label:
            return index

    return None


def _confidence_from_probability(pipeline: Any, text: str, raw_label: Any) -> float | None:
    if not hasattr(pipeline, "predict_proba"):
        return None

    probabilities = pipeline.predict_proba([text])[0]
    class_index = _get_class_index(pipeline, raw_label)

    if class_index is not None:
        return float(probabilities[class_index])

    return float(max(probabilities))


def _confidence_from_decision_function(pipeline: Any, text: str) -> float | None:
    if not hasattr(pipeline, "decision_function"):
        return None

    decision = pipeline.decision_function([text])
    score = decision[0]

    if hasattr(score, "__iter__"):
        score = max(float(value) for value in score)
    else:
        score = float(score)

    # Linear SVM usually exposes margin distance instead of probability. A
    # sigmoid turns the absolute margin into a confidence-like 0..1 value.
    return 1 / (1 + math.exp(-abs(score)))


def predict_sms_with_local_model(text: str) -> dict:
    pipeline = _load_pipeline()

    if pipeline is None:
        _debug("[Local ML] Prediction skipped because the model is unavailable.")
        return _unavailable_result()

    try:
        raw_label = pipeline.predict([text])[0]
        label = _normalize_label(raw_label)
        confidence = _confidence_from_probability(pipeline, text, raw_label)

        if confidence is None:
            confidence = _confidence_from_decision_function(pipeline, text)

        if confidence is None:
            confidence = 0.75

        confidence = round(max(0, min(1, confidence)), 4)
        _debug(
            "[Local ML] Prediction result: "
            f"raw_label={raw_label!r}, mapped_label={label}, confidence={confidence}, "
            f"model_path={_loaded_model_path}"
        )

        return {
            "available": True,
            "label": label,
            "confidence": confidence,
            "reason": "Local ML model prediction completed",
        }
    except Exception as error:
        _debug(f"[Local ML] Prediction error: {error}")
        return _unavailable_result()


def log_local_model_status() -> None:
    pipeline = _load_pipeline()

    if pipeline is None:
        _debug("[Local ML] Startup status: unavailable.")
        return

    _debug(
        "[Local ML] Startup status: ready. "
        f"predict={hasattr(pipeline, 'predict')}, "
        f"predict_proba={hasattr(pipeline, 'predict_proba')}, "
        f"decision_function={hasattr(pipeline, 'decision_function')}"
    )
