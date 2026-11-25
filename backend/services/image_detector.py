from transformers import pipeline
from PIL import Image

# Pretrained AI image detection model
MODEL_NAME = "aaronkantrowitz/ai-human-generated-image-detection"

# Load the model only once
detector = None


def load_model():
    global detector

    if detector is None:
        print("Loading AI image detection model...")
        detector = pipeline(
            "image-classification",
            model=MODEL_NAME
        )
        print("Model loaded successfully!")

    return detector


def detect_image(image_path):
    try:
        model = load_model()

        image = Image.open(image_path).convert("RGB")

        predictions = model(image)

        best_prediction = max(
            predictions,
            key=lambda item: item["score"]
        )

        label = best_prediction["label"]
        confidence = best_prediction["score"]

        if confidence < 0.65:
            result = "Inconclusive"
        elif "AI" in label.upper():
            result = "Likely AI-generated"
        else:
            result = "Likely Human-created"

        return {
            "success": True,
            "result": result,
            "label": label,
            "confidence": round(confidence * 100, 2)
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }