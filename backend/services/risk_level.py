def calculate_risk(prediction: int, confidence: float) -> str:
    if prediction == 1:  
        if confidence >= 0.85:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        else:
            return "low"

    return "low"
