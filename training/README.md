# PRAMAANX - Machine Learning Model Training (Phase 3)

This directory houses the offline training pipelines and Kaggle notebooks for PRAMAANX's self-owned ML models:

1. `image_tampering/`:
   - CASIA v2.0 dataset preprocessing and Error Level Analysis (ELA) generation.
   - EfficientNet-B0 fine-tuning for authentic vs. spliced/copy-move tampered image classification.
   - Grad-CAM heatmap generation pipeline.

2. `malicious_pdf/`:
   - Feature extraction from benign and malicious PDF corpora (e.g. Contagio / CIC-Evasive-PDF).
   - XGBoost classifier training for PDF structural and exploit anomaly detection.

## Zero-Cost AI Policy:
- Training leverages free Kaggle / Colab GPU resources.
- Models are exported as local `.pt` and `.json` weights to run entirely on-premise without external APIs.

