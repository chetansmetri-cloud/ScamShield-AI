import re
from typing import Any


DISCLAIMER = (
    "Rule-based screening is not a legal finding and cannot guarantee that content "
    "is safe or fraudulent."
)

RULES: tuple[tuple[str, str, int, str], ...] = (
    (
        "Urgent pressure",
        r"\b(act now|immediately|urgent|limited time|within \d+ hours|today only)\b",
        12,
        "Pressure to act quickly can reduce time for independent verification.",
    ),
    (
        "Advance payment request",
        r"\b(registration fee|application fee|processing fee|security deposit|placement fee|training fee|interview fee|pay (?:first| upfront)|advance fee)\b",
        25,
        "Upfront fees in an unsolicited offer or request warrant independent verification.",
    ),
    (
        "Guaranteed placement claim",
        r"\b(guaranteed (?:job|placement|internship|employment)|100% placement|assured placement)\b",
        18,
        "Guaranteed employment or placement claims should be checked against the employer's independently published process.",
    ),
    (
        "Sensitive identity or banking data request",
        r"\b(bank account details|banking information|card details|social security number|national identity number|passport number|aadhaar number|send (?:your )?(?:id|identity documents|bank details))\b",
        20,
        "Requests for sensitive identity or banking information before independently verified hiring should be treated cautiously.",
    ),
    (
        "Credential or OTP request",
        r"\b(otp|one[- ]time password|password|login credentials|verification code)\b",
        25,
        "Sharing authentication codes or credentials can enable account takeover.",
    ),
    (
        "Unusually high promised return",
        r"\b(guaranteed (?:income|profit|returns?)|double your money|risk[- ]free profit)\b",
        22,
        "Guaranteed high returns are a common warning sign and need independent checking.",
    ),
    (
        "Threat or account pressure",
        r"\b(account (?:will be|is) (?:blocked|suspended)|legal action|final warning)\b",
        15,
        "Threats designed to trigger immediate compliance are suspicious.",
    ),
    (
        "Unusual payment method",
        r"\b(gift card|crypto(?:currency)?|wire transfer|upi|payment wallet)\b",
        12,
        "Irreversible or unusual payment methods deserve extra verification.",
    ),
)


def classify_score(score: int) -> str:
    if score < 25:
        return "Low risk indicators"
    if score < 50:
        return "Some concerns"
    if score < 75:
        return "Suspicious"
    return "High risk indicators"


def analyze_text(text: str, *, kind: str) -> dict[str, Any]:
    indicators: list[dict[str, Any]] = []
    for name, pattern, points, explanation in RULES:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            indicators.append(
                {
                    "name": name,
                    "explanation": explanation,
                    "evidence": match.group(0),
                    "score_contribution": points,
                    "classification": "inference",
                    "severity": "high" if points >= 20 else "medium",
                }
            )

    score = min(100, sum(item["score_contribution"] for item in indicators))
    return {
        "analysis_method": "rule_based",
        "risk_score": score,
        "risk_category": classify_score(score),
        "confidence": "limited",
        "information_completeness": "text-only",
        "scoring_explanation": (
            f"Score is the sum of matched rule contributions ({sum(i['score_contribution'] for i in indicators)}), "
            "capped at 100. No points are added for missing information."
        ),
        "indicators": indicators,
        "positive_indicators": [],
        "missing_information": [
            "Independent identity and source verification were not performed."
        ],
        "recommended_next_steps": [
            "Verify the sender or organization using contact details obtained independently.",
            "Do not share OTPs, passwords, or payment until independently verified.",
        ],
        "disclaimer": DISCLAIMER,
        "analysis_kind": kind,
    }
