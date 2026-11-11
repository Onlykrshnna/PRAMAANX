"""
PRAMAANX - Test Fixtures Generator (Task 8)
===========================================
Generates standardized variants of an input specimen for forensic regression testing:
1. original.jpg       - Baseline high-resolution image with complete EXIF camera metadata
2. quality_70.jpg     - Recompressed specimen at JPEG quality 70 (triggers low quality rule)
3. resized_1600.jpg   - Resized specimen to 1600px long side without EXIF (triggers messaging rule)
4. exif_stripped.jpg  - Original resolution with all EXIF headers stripped (triggers missing metadata rule)
"""

import io
from pathlib import Path
from PIL import Image, ImageDraw, ExifTags

FIXTURES_DIR = Path(__file__).resolve().parent


def generate_fixtures() -> dict[str, Path]:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Base specimen with rich EXIF metadata
    orig_path = FIXTURES_DIR / "original.jpg"
    w, h = 2400, 1800
    img = Image.new("RGB", (w, h), color=(140, 160, 190))
    draw = ImageDraw.Draw(img)

    # Add geometric features & textures
    draw.rectangle([100, 100, 2300, 1700], outline=(60, 80, 120), width=8)
    draw.ellipse([500, 400, 1900, 1400], fill=(180, 200, 220))
    for i in range(10):
        draw.line([(100, 100 + i * 160), (2300, 1700 - i * 160)], fill=(120, 140, 170), width=3)

    # Attach rich EXIF data
    exif = img.getexif()
    # 0x010F: Make, 0x0110: Model, 0x0131: Software, 0x0132: DateTime, 0x0112: Orientation
    exif[0x010F] = "Nikon"
    exif[0x0110] = "D850 Digital SLR"
    exif[0x0131] = "Ver.1.20"
    exif[0x0132] = "2026:05:14 10:30:00"
    exif[0x0112] = 1

    # Exif SubIFD (0x8769)
    try:
        exif_sub_id = getattr(getattr(ExifTags, "IFD", None), "Exif", 0x8769)
        sub_ifd = exif.get_ifd(exif_sub_id)
        # 0x9003: DateTimeOriginal, 0x9004: DateTimeDigitized
        sub_ifd[0x9003] = "2026:05:14 10:30:00"
        sub_ifd[0x9004] = "2026:05:14 10:30:00"
    except Exception:
        pass

    img.save(orig_path, "JPEG", quality=95, exif=exif)

    # 2. Quality 70 Recompressed specimen
    q70_path = FIXTURES_DIR / "quality_70.jpg"
    img.save(q70_path, "JPEG", quality=70, exif=exif)

    # 3. Resized to 1600px long side, without EXIF (WhatsApp/Messaging-app profile)
    res_path = FIXTURES_DIR / "resized_1600.jpg"
    scale = 1600.0 / max(w, h)
    small_w, small_h = int(w * scale), int(h * scale)
    small_img = img.resize((small_w, small_h), Image.Resampling.LANCZOS)
    small_img.save(res_path, "JPEG", quality=82)  # No EXIF

    # 4. EXIF Stripped specimen (Original resolution, no EXIF)
    stripped_path = FIXTURES_DIR / "exif_stripped.jpg"
    img.save(stripped_path, "JPEG", quality=95)  # No EXIF

    return {
        "original": orig_path,
        "quality_70": q70_path,
        "resized_1600": res_path,
        "exif_stripped": stripped_path,
    }


if __name__ == "__main__":
    generated = generate_fixtures()
    print("Generated test fixtures successfully:")
    for k, v in generated.items():
        print(f" - {k}: {v} ({v.stat().st_size} bytes)")

