"""
OCR module for scam detection system.
Extracts and cleans text from images.
"""

import io
from typing import Union
from backend.utils.logger import logger

OCR_LANG = "vie+eng"
MAX_TEXT_LENGTH = 50000


def extract_text_from_image(image_source: Union[str, bytes]) -> str:
    try:
        import pytesseract
        from PIL import Image
        import cv2
        import numpy as np
    except ImportError as e:
        logger.warning("ocr_dependency_missing | error=%s", str(e))
        return ""

    try:
        # Load image
        if isinstance(image_source, bytes):
            img = Image.open(io.BytesIO(image_source))
        else:
            img = Image.open(image_source)

        img = img.convert("RGB")
        img_np = np.array(img)

        # Preprocess (giống web chongluadao: làm rõ chữ)
        gray = cv2.cvtColor(img_np, cv2.COLOR_RGB2GRAY)
        gray = cv2.medianBlur(gray, 3)
        thresh = cv2.adaptiveThreshold(
            gray, 255,
            cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY,
            31, 2
        )

        img_processed = Image.fromarray(thresh)

        try:
            text = pytesseract.image_to_string(img_processed, lang=OCR_LANG)
        except:
            text = pytesseract.image_to_string(img_processed, lang="eng")

        if not text:
            return ""

        text = " ".join(text.split()).strip()
        return text[:MAX_TEXT_LENGTH]

    except Exception as e:
        logger.warning("ocr_failed | error=%s", str(e))
        return ""