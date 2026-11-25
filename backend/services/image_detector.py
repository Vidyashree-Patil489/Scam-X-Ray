import io
import logging
import os
from PIL import Image

logger = logging.getLogger(__name__)

# Pretrained AI image detection model
MODEL_NAME = os.getenv("IMAGE_MODEL_NAME", "aaronkantrowitz/ai-human-generated-image-detection")

# Minimum confidence threshold for classification; predictions below 0.65 are Inconclusive
CONFIDENCE_THRESHOLD = 0.65

# Explicit mapping derived from model config id2label: {'0': 'human', '1': 'AI-generated'}
LABEL_MAPPING = {
    "AI-generated": "Likely AI-generated",
    "human": "Likely human-created",
}

# Cached pipeline instance
detector = None


class ModelUnavailableError(Exception):
    """Raised when the AI image detection model or its dependencies are unavailable."""
    pass


def load_model():
    """
    Lazy-loads the Hugging Face image classification pipeline on first request.
    Caches the loaded pipeline in memory. Raises ModelUnavailableError if
    transformers/torch is missing or if model downloading/loading fails.
    """
    global detector

    model_name = os.getenv("IMAGE_MODEL_NAME", MODEL_NAME)

    if detector is None or getattr(detector, "_model_name", None) != model_name:
        logger.info("Loading AI image detection model '%s'...", model_name)
        try:
            from transformers import pipeline
        except ImportError as err:
            logger.error("Image detection dependencies (transformers/torch) not installed: %s", err)
            raise ModelUnavailableError("Image detection dependencies are missing") from err

        try:
            detector = pipeline(
                "image-classification",
                model=model_name
            )
            detector._model_name = model_name
            logger.info("AI image detection model loaded successfully.")
        except Exception as err:
            logger.exception("Failed to load or initialize AI image detection model '%s': %s", model_name, err)
            raise ModelUnavailableError("Failed to initialize image detection model") from err

    return detector


def detect_image(image_input):
    """
    Classifies an in-memory image as likely AI-generated or likely human-created.
    Accepts a PIL Image, raw bytes, bytearray, or a file-like stream.
    Processes the image entirely in memory with no disk writes.
    """
    model = load_model()

    try:
        if isinstance(image_input, Image.Image):
            image = image_input.convert("RGB")
        elif isinstance(image_input, (bytes, bytearray)):
            image = Image.open(io.BytesIO(image_input)).convert("RGB")
        elif hasattr(image_input, "read"):
            image = Image.open(image_input).convert("RGB")
        else:
            raise ValueError("Unsupported image input type; expected PIL Image or bytes")

        predictions = model(image)

        best_prediction = max(
            predictions,
            key=lambda item: item["score"]
        )

        label = best_prediction["label"]
        confidence = float(best_prediction["score"])

        # Determine probability-based verdict
        if confidence < CONFIDENCE_THRESHOLD:
            result = "Inconclusive"
        elif label in LABEL_MAPPING:
            result = LABEL_MAPPING[label]
        else:
            # Unknown labels must produce Inconclusive, never a guess
            result = "Inconclusive"

        return {
            "success": True,
            "result": result,
            "label": label,
            "confidence": round(confidence * 100, 2),
            "all_predictions": [
                {
                    "label": item["label"],
                    "confidence": round(item["score"] * 100, 2)
                }
                for item in predictions
            ]
        }
    except ModelUnavailableError:
        raise
    except Exception as err:
        logger.exception("Unexpected error during image classification: %s", err)
        raise
