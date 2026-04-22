"""Text ML package — lazy exports to reduce import-time cycles."""

__all__ = ["analyze_text", "predict_text_scam"]


def analyze_text(text: str):
    from ml.text.analyzer import analyze_text as _fn
    return _fn(text)


def predict_text_scam(text: str, source: str = "text"):
    from ml.text.predict_text import predict_text_scam as _fn
    return _fn(text, source)
