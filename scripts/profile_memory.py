"""
Memory profiler for PRAMAANX backend imports and startup.
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

print(f"Base Python Memory: {get_process_memory_mb():.2f} MB")

mem_before_app = get_process_memory_mb()
print("\n--- Importing backend.main (current behavior) ---")
import backend.main
mem_after_app = get_process_memory_mb()
print(f"[backend.main] Delta: +{mem_after_app - mem_before_app:6.2f} MB | Total: {mem_after_app:6.2f} MB")

print("\n--- Checking PyTorch CUDA status ---")
import torch
print(f"torch.cuda.is_available(): {torch.cuda.is_available()}")
print(f"torch.__version__: {torch.__version__}")
