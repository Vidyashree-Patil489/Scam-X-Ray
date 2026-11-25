import argparse
import contextlib
import csv
import logging
import os
import sys
import warnings
from pathlib import Path

# Suppress all library logging and warnings before importing transformers or torch
os.environ["HF_HUB_DISABLE_SYMLINKS_WARNING"] = "1"
os.environ["TRANSFORMERS_NO_ADVISORY_WARNINGS"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)

# Add backend directory to path so services can be imported
_SCRIPT_DIR = Path(__file__).resolve().parent
_BACKEND_DIR = _SCRIPT_DIR.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from PIL import Image
import services.image_detector as image_detector


DEFAULT_MODEL = "aaronkantrowitz/ai-human-generated-image-detection"
CANDIDATE_MODELS = [
    "aaronkantrowitz/ai-human-generated-image-detection",
    "dima806/ai_vs_human_generated_image_detection",
    "Ateeqq/ai-vs-human-image-detector",
    "dima806/ai_vs_real_image_detection",
]


@contextlib.contextmanager
def suppress_stderr():
    """Redirect stderr to devnull to prevent Hugging Face download progress or warnings."""
    with open(os.devnull, "w") as devnull:
        old_stderr = sys.stderr
        try:
            sys.stderr = devnull
            yield
        finally:
            sys.stderr = old_stderr


def sanitize_filename(name: str) -> str:
    """Creates a filesystem-friendly string for CSV names."""
    return name.replace("/", "_").replace("\\", "_").replace(":", "_")


def resolve_model_labels(id2label: dict) -> tuple[str, str]:
    """
    Identifies the AI-class and Human-class label strings from the model's id2label dict.
    Returns (ai_label, human_label).
    """
    ai_label = None
    human_label = None

    for _, label in id2label.items():
        lower = label.lower()
        if "ai" in lower or "fake" in lower or "synth" in lower or "gen" in lower:
            ai_label = label
        elif "hum" in lower or "real" in lower:
            human_label = label

    # Fallbacks if unconventional names
    if not ai_label or not human_label:
        values = list(id2label.values())
        if len(values) >= 2:
            return values[1], values[0]

    return ai_label, human_label


def evaluate_model(model_id: str, eval_dir: Path, output_dir: Path) -> dict:
    """
    Evaluates a single model against images in eval_dir/ai and eval_dir/real.
    Runs each image through the exact same code path (image_detector.detect_image).
    Writes CSV results and returns the summary statistics.
    """
    os.environ["IMAGE_MODEL_NAME"] = model_id

    # Load model and configure label mapping
    with suppress_stderr():
        detector = image_detector.load_model()
        id2label = getattr(getattr(detector, "model", None), "config", None)
        id2label_map = getattr(id2label, "id2label", {}) if id2label else {}

    ai_label_name, human_label_name = resolve_model_labels(id2label_map)

    # Configure services.image_detector.LABEL_MAPPING for this candidate model
    image_detector.LABEL_MAPPING = {
        ai_label_name: "Likely AI-generated",
        human_label_name: "Likely human-created",
    }

    # Collect images
    ai_dir = eval_dir / "ai"
    real_dir = eval_dir / "real"

    image_tasks = []
    if ai_dir.exists():
        for p in sorted(ai_dir.iterdir()):
            if p.is_file() and p.suffix.lower() in [".jpg", ".jpeg", ".png", ".webp"]:
                image_tasks.append((p, "AI"))

    if real_dir.exists():
        for p in sorted(real_dir.iterdir()):
            if p.is_file() and p.suffix.lower() in [".jpg", ".jpeg", ".png", ".webp"]:
                image_tasks.append((p, "real"))

    if not image_tasks:
        return {"empty": True}

    rows = []
    correct_count = 0
    false_negatives = 0  # AI classified as human
    false_positives = 0  # Real classified as AI
    inconclusive_count = 0

    for path, true_label in image_tasks:
        try:
            with Image.open(path) as img:
                with suppress_stderr():
                    res = image_detector.detect_image(img)

            verdict = res["result"]
            all_preds = {item["label"]: item["confidence"] for item in res.get("all_predictions", [])}

            ai_prob = all_preds.get(ai_label_name, 0.0)
            human_prob = all_preds.get(human_label_name, 0.0)

            # Check correctness
            if true_label == "AI" and verdict == "Likely AI-generated":
                correct = True
            elif true_label == "real" and verdict == "Likely human-created":
                correct = True
            else:
                correct = False

            if correct:
                correct_count += 1

            if true_label == "AI" and verdict == "Likely human-created":
                false_negatives += 1
            elif true_label == "real" and verdict == "Likely AI-generated":
                false_positives += 1

            if verdict == "Inconclusive":
                inconclusive_count += 1

            rows.append({
                "file": path.name,
                "true_label": true_label,
                "verdict": verdict,
                "ai_prob": ai_prob,
                "human_prob": human_prob,
                "correct": correct,
            })
        except Exception:
            rows.append({
                "file": path.name,
                "true_label": true_label,
                "verdict": "Error",
                "ai_prob": 0.0,
                "human_prob": 0.0,
                "correct": False,
            })

    total = len(rows)
    accuracy = round((correct_count / total) * 100, 2) if total > 0 else 0.0

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write CSV
    csv_file = output_dir / f"{sanitize_filename(model_id)}_eval.csv"
    with open(csv_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "true_label", "model_verdict", "ai_probability", "human_probability"])
        for r in rows:
            writer.writerow([r["file"], r["true_label"], r["verdict"], r["ai_prob"], r["human_prob"]])

    summary = {
        "model": model_id,
        "total": total,
        "correct": correct_count,
        "accuracy": accuracy,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "inconclusive": inconclusive_count,
        "csv_path": str(csv_file),
        "rows": rows,
    }

    return summary


def print_single_model_report(summary: dict):
    """Prints the per-image table and summary counts formatted strictly with names and numbers."""
    model_id = summary["model"]
    rows = summary["rows"]

    print("=" * 110)
    print(f"MODEL: {model_id}")
    print("=" * 110)

    # Per-image table header
    header_fmt = "{:<55} | {:<10} | {:<22} | {:>10} | {:>10}"
    row_fmt = "{:<55} | {:<10} | {:<22} | {:>10.2f} | {:>10.2f}"

    print(header_fmt.format("File", "True Label", "Model Verdict", "AI Prob (%)", "Human Prob (%)"))
    print("-" * 110)

    for r in rows:
        name = r["file"]
        if len(name) > 53:
            name = name[:50] + "..."
        print(row_fmt.format(name, r["true_label"], r["verdict"], r["ai_prob"], r["human_prob"]))

    print("-" * 110)
    print("SUMMARY COUNTS:")
    print(f"Total Images: {summary['total']}")
    print(f"Correct Predictions: {summary['correct']}")
    print(f"Accuracy: {summary['accuracy']}%")
    print(f"False Negatives (AI classified as human): {summary['false_negatives']}")
    print(f"False Positives (Real classified as AI): {summary['false_positives']}")
    print(f"Inconclusive Verdicts: {summary['inconclusive']}")
    print(f"CSV Written: {summary['csv_path']}")
    print("=" * 110)
    print()


def print_comparison_table(summaries: list[dict]):
    """Prints a side-by-side comparison table of all evaluated models."""
    print("=" * 115)
    print("MODEL COMPARISON TABLE")
    print("=" * 115)
    fmt = "{:<48} | {:>5} | {:>7} | {:>12} | {:>15} | {:>15} | {:>12}"
    print(fmt.format("Model ID", "Total", "Correct", "Accuracy (%)", "False Negatives", "False Positives", "Inconclusive"))
    print("-" * 115)
    for s in summaries:
        print(fmt.format(
            s["model"],
            s["total"],
            s["correct"],
            f"{s['accuracy']:.2f}%",
            s["false_negatives"],
            s["false_positives"],
            s["inconclusive"]
        ))
    print("=" * 115)


def main():
    parser = argparse.ArgumentParser(description="Evaluate AI image detection models on local test sets.")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help="Hugging Face model ID to evaluate")
    parser.add_argument("--all", action="store_true", help="Evaluate current model and candidate models")
    parser.add_argument("--eval-dir", type=str, default=str(_BACKEND_DIR / "eval_images"), help="Path to eval_images directory")
    parser.add_argument("--output-dir", type=str, default=str(_BACKEND_DIR / "eval_results"), help="Path to eval_results directory")
    args = parser.parse_args()

    eval_dir = Path(args.eval_dir).resolve()
    output_dir = Path(args.output_dir).resolve()

    # Check image directories
    ai_dir = eval_dir / "ai"
    real_dir = eval_dir / "real"
    ai_count = len([p for p in ai_dir.iterdir() if p.is_file()]) if ai_dir.exists() else 0
    real_count = len([p for p in real_dir.iterdir() if p.is_file()]) if real_dir.exists() else 0

    if ai_count == 0 and real_count == 0:
        print("NO_IMAGES_FOUND: backend/eval_images/ai and backend/eval_images/real contain no images.")
        sys.exit(0)

    models_to_run = CANDIDATE_MODELS if args.all else [args.model]
    summaries = []

    for model_id in models_to_run:
        summary = evaluate_model(model_id, eval_dir, output_dir)
        if summary.get("empty"):
            print("NO_IMAGES_FOUND: backend/eval_images/ai and backend/eval_images/real contain no images.")
            sys.exit(0)
        print_single_model_report(summary)
        summaries.append(summary)

    if len(summaries) > 1:
        print_comparison_table(summaries)


if __name__ == "__main__":
    main()
