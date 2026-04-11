"""
OCR engine for text extraction from images.

Provides OCR functionality with Vietnamese support.
"""

import os
import sys
from pathlib import Path
from typing import Optional, List, Tuple
from utils.logger import logger
from config import OCR_LANGUAGE, OCR_TIMEOUT

# Try to import pytesseract
try:
    import pytesseract
    from PIL import Image
    OCR_AVAILABLE = True
except ImportError:
    OCR_AVAILABLE = False
    logger.warning("pytesseract not available | OCR disabled")


class OCREngine:
    """OCR text extraction engine."""
    
    @staticmethod
    def check_tesseract():
        """
        Check if Tesseract is installed and accessible.
        
        Returns:
            bool: True if Tesseract is available
        """
        if not OCR_AVAILABLE:
            return False
        
        try:
            pytesseract.get_tesseract_version()
            logger.info("tesseract_found | path=%s", pytesseract.pytesseract.get_tesseract_version())
            return True
        except Exception as e:
            logger.warning("tesseract_not_found | error=%s", str(e))
            return False
    
    @staticmethod
    def extract_text(image_path: str) -> Tuple[str, Dict]:
        """
        Extract text from image using OCR.
        
        Args:
            image_path: Path to image file
            
        Returns:
            tuple: (extracted_text, metadata)
        """
        try:
            if not OCR_AVAILABLE:
                logger.warning("ocr_not_available")
                return "", {"error": "OCR not available", "confidence": 0}
            
            # Load image
            image = Image.open(image_path)
            
            # Resize image if too small (improves OCR)
            width, height = image.size
            if width < 300 or height < 300:
                scale_factor = max(300 / width, 300 / height)
                new_size = (int(width * scale_factor), int(height * scale_factor))
                image = image.resize(new_size, Image.Resampling.LANCZOS)
            
            # Extract text
            text = pytesseract.image_to_string(
                image,
                lang=OCR_LANGUAGE,
                timeout=OCR_TIMEOUT,
                config='--psm 6'  # PSM 6: assume a single uniform block of text
            )
            
            # Get detailed results
            data = pytesseract.image_to_data(
                image,
                lang=OCR_LANGUAGE,
                timeout=OCR_TIMEOUT,
                output_type='dict'
            )
            
            # Calculate confidence
            confidences = [int(conf) for conf in data['confidence'] if int(conf) > 0]
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0
            
            metadata = {
                'confidence': avg_confidence / 100.0,
                'word_count': len([c for c in data['confidence'] if int(c) > 0]),
                'image_size': (width, height),
                'language': OCR_LANGUAGE
            }
            
            logger.info(
                "ocr_extraction_success | confidence=%.2f | words=%d",
                metadata['confidence'],
                metadata['word_count']
            )
            
            return text.strip(), metadata
            
        except Exception as e:
            logger.error("ocr_extraction_failed | error=%s", str(e))
            return "", {"error": str(e), "confidence": 0}
    
    @staticmethod
    def extract_text_from_region(image_path: str, bbox: Tuple[int, int, int, int]) -> str:
        """
        Extract text from specific region of image.
        
        Args:
            image_path: Path to image file
            bbox: Bounding box (left, top, right, bottom)
            
        Returns:
            str: Extracted text
        """
        try:
            if not OCR_AVAILABLE:
                return ""
            
            image = Image.open(image_path)
            region = image.crop(bbox)
            
            text = pytesseract.image_to_string(
                region,
                lang=OCR_LANGUAGE,
                timeout=OCR_TIMEOUT
            )
            
            return text.strip()
            
        except Exception as e:
            logger.error("ocr_region_extraction_failed | error=%s", str(e))
            return ""
    
    @staticmethod
    def extract_text_batch(image_paths: List[str]) -> List[Tuple[str, dict]]:
        """
        Extract text from multiple images.
        
        Args:
            image_paths: List of image file paths
            
        Returns:
            list: List of (text, metadata) tuples
        """
        results = []
        for image_path in image_paths:
            text, metadata = OCREngine.extract_text(image_path)
            results.append((text, metadata))
        return results


def extract_text_from_image(image_path: str) -> Tuple[str, dict]:
    """
    Convenience function to extract text from image.
    
    Args:
        image_path: Path to image file
        
    Returns:
        tuple: (extracted_text, metadata)
    """
    return OCREngine.extract_text(image_path)
