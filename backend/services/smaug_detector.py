import sys
from huggingface_hub import snapshot_download
from PIL import Image

detector = None


def load_model():
    global detector

    if detector is None:
        print("Downloading/loading Smaug AI Image Detector...")

        model_path = snapshot_download(
            "abacusai/Smaug-AI-Image-Detector"
        )

        if model_path not in sys.path:
            sys.path.insert(0, model_path)

        from smaug_image_detect import SmaugImageDetect

        detector = SmaugImageDetect.from_pretrained(model_path)

        print("Smaug model loaded successfully!")

    return detector


def detect_image(image_input):
    try:
        model = load_model()

        if isinstance(image_input, Image.Image):
            image = image_input.convert("RGB")
        else:
            with Image.open(image_input) as source:
                image = source.convert("RGB")

        ai_probability = float(model(image))

        human_probability = 1.0 - ai_probability

        if ai_probability >= 0.5:
            result = "Likely AI-generated"
            label = "AI-generated"
        else:
            result = "Likely Human-created"
            label = "human"

        return {
            "success": True,
            "result": result,
            "label": label,
            "confidence": round(max(ai_probability, human_probability) * 100, 2),
            "all_predictions": [
                {
                    "label": "AI-generated",
                    "confidence": round(ai_probability * 100, 2)
                },
                {
                    "label": "human",
                    "confidence": round(human_probability * 100, 2)
                }
            ]
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }