"""
Lifecycle memory profiler for PRAMAANX.
"""
import os
import sys
from pathlib import Path
import psutil
import gc

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))

def get_process_memory_mb():
    gc.collect()
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)

print("=" * 60)
print("PRAMAANX LIFECYCLE MEMORY PROFILE")
print("=" * 60)

# 0. Python Base
m0 = get_process_memory_mb()
print(f"0. Python Base:             {m0:6.2f} MB")

# 1. FastAPI App Startup
import backend.main
m1 = get_process_memory_mb()
print(f"1. FastAPI App Startup:     {m1:6.2f} MB (Delta: +{m1 - m0:6.2f} MB)")

# 2. Health Checks Run
h1 = backend.main.health_check()
h2 = backend.main.api_v1_health()
m2 = get_process_memory_mb()
print(f"2. Health Checks Run:       {m2:6.2f} MB (Delta: +{m2 - m1:6.2f} MB)")
print(f"   /health engine:          {h1['engine']}")
print(f"   Is PyTorch in memory?    {'torch' in sys.modules}")

# 3. First Model Load (Singleton)
from backend.analyzers.image import get_tamper_model
m3_before = get_process_memory_mb()
model, meta = get_tamper_model()
m3_after = get_process_memory_mb()
print(f"3. First Model Load (CPU):  {m3_after:6.2f} MB (Delta: +{m3_after - m3_before:6.2f} MB)")
print(f"   Architecture:            {meta.get('architecture')}, Training: {model.training}")

# 4. Second Model Access (Singleton check)
m4_before = get_process_memory_mb()
model2, meta2 = get_tamper_model()
m4_after = get_process_memory_mb()
print(f"4. Second Model Access:     {m4_after:6.2f} MB (Delta: +{m4_after - m4_before:6.2f} MB)")
assert model is model2, "Model singleton failed!"

# 5. Full Image Analysis (Inference + ELA + GradCAM)
from PIL import Image
import tempfile
test_img_path = Path(tempfile.gettempdir()) / "test_lifecycle_specimen.jpg"
img = Image.new("RGB", (300, 300), color=(128, 64, 32))
img.save(test_img_path, format="JPEG")

from backend.analyzers.image import analyze_image
m5_before = get_process_memory_mb()
report = analyze_image(test_img_path, generate_gradcam=True, generate_ela=True)
m5_after = get_process_memory_mb()
print(f"5. Image Analysis Run:      {m5_after:6.2f} MB (Delta: +{m5_after - m5_before:6.2f} MB)")
print(f"   Predicted class:         {report.ml_prediction.get('predicted_class')}")
print(f"   Confidence:              {report.ml_prediction.get('confidence')}")
print(f"   Visual artifacts:        {list(report.visual_evidence.keys())}")

if test_img_path.exists():
    test_img_path.unlink()

print("=" * 60)
print(f"PEAK RESIDENT MEMORY (RSS): {get_process_memory_mb():6.2f} MB")
print("=" * 60)
