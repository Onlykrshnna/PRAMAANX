# Malicious PDF Classifier Training (Phase 3)

Planned architecture:
- Model: XGBoost Classifier
- Features: 20+ structural count and anomaly indicators (JavaScript, /Launch, /EmbeddedFiles, obj/endobj mismatches, stream entropy)
- Output artifact: `backend/models/malpdf_xgb.json`

