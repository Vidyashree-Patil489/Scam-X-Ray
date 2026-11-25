import io
import os
import sys
import unittest
from unittest.mock import patch, MagicMock
from PIL import Image

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from app import app
from services.image_detector import ModelUnavailableError


class TestImageAPI(unittest.TestCase):
    """Integration tests for the /analyze-image route using a mocked model."""

    def setUp(self):
        self.client = app.test_client()

    def _make_image_bytes(self, fmt="JPEG", size=(32, 32), color="blue"):
        img = Image.new("RGB", size, color=color)
        buf = io.BytesIO()
        img.save(buf, format=fmt)
        return buf.getvalue()

    @patch("services.image_detector.load_model")
    def test_valid_jpeg_image(self, mock_load_model):
        """Valid JPEG image returns 200 and detection result."""
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = [
            {"label": "AI-generated", "score": 0.95},
            {"label": "human", "score": 0.05},
        ]
        mock_load_model.return_value = mock_pipeline

        img_bytes = self._make_image_bytes("JPEG")
        data = {
            "image": (io.BytesIO(img_bytes), "sample.jpg", "image/jpeg")
        }
        res = self.client.post("/analyze-image", data=data, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 200)
        json_data = res.get_json()
        self.assertTrue(json_data["success"])
        self.assertEqual(json_data["result"], "Likely AI-generated")
        self.assertEqual(json_data["confidence"], 95.0)

    @patch("services.image_detector.load_model")
    def test_valid_png_and_webp_images(self, mock_load_model):
        """PNG and WebP images are accepted and correctly processed."""
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = [
            {"label": "human", "score": 0.91},
            {"label": "AI-generated", "score": 0.09},
        ]
        mock_load_model.return_value = mock_pipeline

        # Test PNG
        png_bytes = self._make_image_bytes("PNG")
        res_png = self.client.post(
            "/analyze-image",
            data={"image": (io.BytesIO(png_bytes), "sample.png", "image/png")},
            content_type="multipart/form-data"
        )
        self.assertEqual(res_png.status_code, 200)
        self.assertEqual(res_png.get_json()["result"], "Likely human-created")

        # Test WebP
        webp_bytes = self._make_image_bytes("WEBP")
        res_webp = self.client.post(
            "/analyze-image",
            data={"image": (io.BytesIO(webp_bytes), "sample.webp", "image/webp")},
            content_type="multipart/form-data"
        )
        self.assertEqual(res_webp.status_code, 200)
        self.assertEqual(res_webp.get_json()["result"], "Likely human-created")

    def test_non_image_file_renamed_jpg(self):
        """A text/binary non-image file renamed .jpg is rejected with 400 Bad Request."""
        text_data = b"This is plain text pretending to be a JPG image file."
        data = {
            "image": (io.BytesIO(text_data), "fake.jpg", "image/jpeg")
        }
        res = self.client.post("/analyze-image", data=data, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 400)
        json_data = res.get_json()
        self.assertFalse(json_data["success"])
        self.assertIn("Invalid or corrupted image", json_data["error"])

    def test_empty_file(self):
        """An empty file (0 bytes) is rejected with 400 Bad Request."""
        data = {
            "image": (io.BytesIO(b""), "empty.jpg", "image/jpeg")
        }
        res = self.client.post("/analyze-image", data=data, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 400)
        json_data = res.get_json()
        self.assertFalse(json_data["success"])
        self.assertIn("empty", json_data["error"].lower())

    def test_missing_image_field(self):
        """Request missing the 'image' form field returns 400."""
        res = self.client.post("/analyze-image", data={}, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json()["success"])

    def test_empty_filename(self):
        """Request with an empty filename returns 400."""
        data = {
            "image": (io.BytesIO(b"data"), "", "image/jpeg")
        }
        res = self.client.post("/analyze-image", data=data, content_type="multipart/form-data")
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json()["success"])

    def test_oversized_file(self):
        """Files exceeding 5 MB are rejected with 413 Payload Too Large."""
        oversized_data = b"0" * (5 * 1024 * 1024 + 100)
        data = {
            "image": (io.BytesIO(oversized_data), "large.jpg", "image/jpeg")
        }
        res = self.client.post("/analyze-image", data=data, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 413)
        json_data = res.get_json()
        self.assertFalse(json_data["success"])
        self.assertIn("5 MB", json_data["error"])

    def test_unsupported_image_type(self):
        """Valid image in unsupported format (e.g. BMP) is rejected with 415 Unsupported Media Type."""
        bmp_bytes = self._make_image_bytes("BMP")
        data = {
            "image": (io.BytesIO(bmp_bytes), "sample.bmp", "image/bmp")
        }
        res = self.client.post("/analyze-image", data=data, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 415)
        json_data = res.get_json()
        self.assertFalse(json_data["success"])
        self.assertIn("Unsupported image format", json_data["error"])

    @patch("services.image_detector.load_model")
    def test_unknown_label_inconclusive(self, mock_load_model):
        """An unknown model label produces an 'Inconclusive' result in the API response."""
        mock_pipeline = MagicMock()
        mock_pipeline.return_value = [
            {"label": "unrecognized_category", "score": 0.98},
            {"label": "human", "score": 0.02},
        ]
        mock_load_model.return_value = mock_pipeline

        img_bytes = self._make_image_bytes("JPEG")
        data = {
            "image": (io.BytesIO(img_bytes), "photo.jpg", "image/jpeg")
        }
        res = self.client.post("/analyze-image", data=data, content_type="multipart/form-data")

        self.assertEqual(res.status_code, 200)
        json_data = res.get_json()
        self.assertTrue(json_data["success"])
        self.assertEqual(json_data["result"], "Inconclusive")

    def test_transformers_not_installed_503_and_analyze_still_works(self):
        """
        When transformers/torch is missing or model unavailable, /analyze-image returns 503
        while /analyze text and URL scans still start and work normally.
        """
        img_bytes = self._make_image_bytes("JPEG")
        data = {
            "image": (io.BytesIO(img_bytes), "photo.jpg", "image/jpeg")
        }

        # In this test environment, transformers is not installed, so calling /analyze-image
        # without mocking will naturally encounter the missing dependencies or ModelUnavailableError.
        with patch("services.image_detector.load_model", side_effect=ModelUnavailableError("Missing dependency")):
            res_image = self.client.post("/analyze-image", data=data, content_type="multipart/form-data")

            self.assertEqual(res_image.status_code, 503)
            json_data = res_image.get_json()
            self.assertFalse(json_data["success"])
            self.assertEqual(json_data["error"], "Image detection is temporarily unavailable")

        # Verify /analyze text scan still works normally
        text_payload = {
            "text": "Software Engineer position at reputable organization with competitive salary."
        }
        res_text = self.client.post("/analyze", json=text_payload)
        self.assertEqual(res_text.status_code, 200)
        data_text = res_text.get_json()
        self.assertIn("risk_score", data_text)
        self.assertIn("risk_level", data_text)

        # Verify /analyze URL scan still works normally
        url_payload = {
            "url": "https://example.com"
        }
        res_url = self.client.post("/analyze", json=url_payload)
        self.assertEqual(res_url.status_code, 200)
        data_url = res_url.get_json()
        self.assertIn("risk_score", data_url)


if __name__ == "__main__":
    unittest.main()
