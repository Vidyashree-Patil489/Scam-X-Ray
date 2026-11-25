import io
import os
import sys
import unittest
from unittest.mock import patch, MagicMock
from PIL import Image

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from services.image_detector import (
    detect_image,
    ModelUnavailableError,
    CONFIDENCE_THRESHOLD,
    LABEL_MAPPING,
)


class TestImageDetectionService(unittest.TestCase):
    """Unit tests for services/image_detector.py with a mocked model."""

    def setUp(self):
        # Create a small valid test image in memory
        self.img = Image.new("RGB", (64, 64), color=(200, 100, 50))
        buf = io.BytesIO()
        self.img.save(buf, format="JPEG")
        self.img_bytes = buf.getvalue()

    @patch("services.image_detector.load_model")
    def test_detect_image_likely_ai(self, mock_load_model):
        """High-confidence AI-generated label maps to 'Likely AI-generated'."""
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = [
            {"label": "AI-generated", "score": 0.942},
            {"label": "human", "score": 0.058},
        ]
        mock_load_model.return_value = mock_pipeline

        res = detect_image(self.img)

        self.assertTrue(res["success"])
        self.assertEqual(res["result"], "Likely AI-generated")
        self.assertEqual(res["label"], "AI-generated")
        self.assertEqual(res["confidence"], 94.2)
        self.assertEqual(len(res["all_predictions"]), 2)

    @patch("services.image_detector.load_model")
    def test_detect_image_likely_human(self, mock_load_model):
        """High-confidence human label maps to 'Likely human-created'."""
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = [
            {"label": "human", "score": 0.887},
            {"label": "AI-generated", "score": 0.113},
        ]
        mock_load_model.return_value = mock_pipeline

        res = detect_image(self.img_bytes)

        self.assertTrue(res["success"])
        self.assertEqual(res["result"], "Likely human-created")
        self.assertEqual(res["label"], "human")
        self.assertEqual(res["confidence"], 88.7)

    @patch("services.image_detector.load_model")
    def test_detect_image_low_confidence_inconclusive(self, mock_load_model):
        """Confidence score below 0.65 threshold produces 'Inconclusive'."""
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = [
            {"label": "AI-generated", "score": 0.58},
            {"label": "human", "score": 0.42},
        ]
        mock_load_model.return_value = mock_pipeline

        res = detect_image(self.img)

        self.assertTrue(res["success"])
        self.assertEqual(res["result"], "Inconclusive")
        self.assertEqual(res["confidence"], 58.0)

    @patch("services.image_detector.load_model")
    def test_detect_image_unknown_label_inconclusive(self, mock_load_model):
        """Unknown or unexpected model label produces 'Inconclusive', never a guess."""
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = [
            {"label": "synthetic_deepfake_unknown", "score": 0.99},
            {"label": "human", "score": 0.01},
        ]
        mock_load_model.return_value = mock_pipeline

        res = detect_image(self.img)

        self.assertTrue(res["success"])
        self.assertEqual(res["result"], "Inconclusive")
        self.assertEqual(res["label"], "synthetic_deepfake_unknown")

    @patch("services.image_detector.load_model")
    def test_detect_image_input_types(self, mock_load_model):
        """Accepts PIL Image, raw bytes, and file-like stream objects."""
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = [
            {"label": "human", "score": 0.92},
            {"label": "AI-generated", "score": 0.08},
        ]
        mock_load_model.return_value = mock_pipeline

        # PIL Image
        res_pil = detect_image(self.img)
        self.assertEqual(res_pil["result"], "Likely human-created")

        # Bytes
        res_bytes = detect_image(self.img_bytes)
        self.assertEqual(res_bytes["result"], "Likely human-created")

        # BytesIO
        res_stream = detect_image(io.BytesIO(self.img_bytes))
        self.assertEqual(res_stream["result"], "Likely human-created")

    @patch("services.image_detector.load_model")
    def test_model_unavailable_error_propagates(self, mock_load_model):
        """When load_model fails, ModelUnavailableError propagates cleanly."""
        mock_load_model.side_effect = ModelUnavailableError("Dependencies missing")

        with self.assertRaises(ModelUnavailableError):
            detect_image(self.img)


if __name__ == "__main__":
    unittest.main()
