
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .risk_engine import Transaction, analyze_transaction
from .storage import load_transactions, add_transaction
from .fraud_graph import FraudGraph

app = FastAPI(
    title="Payment Risk Assistant",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# DEFAULT TRANSACTIONS
# =========================================================

default_transactions = [
    Transaction(
        user_id="user_001",
        amount=1000,
        recipient="merchant_101",
        device="device_A",
        location="Ludhiana",
        timestamp="2026-09-18 10:00:00"
    ),
    Transaction(
        user_id="user_001",
        amount=950,
        recipient="merchant_101",
        device="device_A",
        location="Ludhiana",
        timestamp="2026-09-18 12:00:00"
    ),
    Transaction(
        user_id="user_001",
        amount=1100,
        recipient="merchant_205",
        device="device_A",
        location="Ludhiana",
        timestamp="2026-09-18 14:00:00"
    )
]


transactions = load_transactions(default_transactions)


# =========================================================
# REQUEST MODELS
# =========================================================

class PaymentRequest(BaseModel):
    user_id: str
    amount: float
    recipient: str
    device: str
    location: str
    timestamp: str
    message: str = ""
    qr_recipient: str = ""
    qr_amount: float | None = None


class LearnRequest(BaseModel):
    user_id: str
    amount: float
    recipient: str
    device: str
    location: str
    timestamp: str
    approved: bool


# =========================================================
# USER-FRIENDLY EXPLANATION
# =========================================================

def generate_user_message(result, graph_risk, final_score):

    reasons = []

    if result["amount"]["risk"] > 0:
        reasons.append(
            "The payment amount is unusual compared with normal behavior."
        )

    if result["recipient"]["risk"] > 0:
        reasons.append(
            "The recipient is new or has limited history."
        )

    if result["device"]["risk"] > 0:
        reasons.append(
            "The payment is coming from an unfamiliar device."
        )

    if result["location"]["risk"] > 0:
        reasons.append(
            "The payment location is unusual."
        )

    if result["message"]["risk"] > 0:
        reasons.append(
            "The payment message contains suspicious language."
        )

    if result["qr"]["risk"] > 0:
        reasons.append(
            "The QR payment details do not fully match."
        )

    if result["frequency"]["risk"] > 0:
        reasons.append(
            "Multiple payments occurred within a short time."
        )

    if graph_risk["graph_risk_score"] > 0:
        reasons.append(
            "The account has connections with other users "
            "through shared payment entities."
        )

    if not reasons:
        return (
            "This payment looks consistent with the user's "
            "normal behavior."
        )

    if final_score >= 75:
        message = (
            "This payment has multiple risk signals "
            "and requires strong verification before proceeding."
        )

    elif final_score >= 50:
        message = (
            "This payment shows several unusual signals. "
            "Additional verification is recommended."
        )

    elif final_score >= 25:
        message = (
            "This payment has some unusual characteristics. "
            "Review the payment details before proceeding."
        )

    else:
        message = (
            "The payment has a low overall risk score, "
            "but some unusual signals were detected."
        )

    return message + " Reasons: " + " ".join(reasons)


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():

    return {
        "status": "online",
        "service": "Payment Risk Assistant",
        "version": "1.0.0"
    }


# =========================================================
# ANALYZE PAYMENT
# =========================================================

@app.post("/analyze")
def analyze_payment(request: PaymentRequest):

    transaction = Transaction(
        user_id=request.user_id,
        amount=request.amount,
        recipient=request.recipient,
        device=request.device,
        location=request.location,
        timestamp=request.timestamp
    )

    # Behavioral analysis
    result = analyze_transaction(
        transaction,
        transactions,
        request.message,
        {
            "recipient": request.qr_recipient,
            "amount": request.qr_amount
        }
    )

    # Build graph
    graph = FraudGraph()

    graph.build_from_transactions(
        transactions
    )

    # Graph risk
    graph_risk = graph.get_user_graph_risk(
        request.user_id
    )

    graph_connections = graph.get_user_connections(
        request.user_id
    )

    # Combine behavioral + graph risk
    behavioral_score = result["risk_score"]

    graph_score = graph_risk["graph_risk_score"]

    final_score = min(
        behavioral_score + graph_score,
        100
    )

    # Final risk level + action
    if final_score >= 75:

        final_level = "HIGH"

        final_action = (
            "BLOCK / REQUIRE STRONG VERIFICATION"
        )

    elif final_score >= 50:

        final_level = "MEDIUM"

        final_action = (
            "REQUIRE ADDITIONAL VERIFICATION"
        )

    elif final_score >= 25:

        final_level = "LOW"

        final_action = "SHOW WARNING"

    else:

        final_level = "SAFE"

        final_action = "ALLOW"

    # User explanation
    user_message = generate_user_message(
        result,
        graph_risk,
        final_score
    )

    return {

        "transaction": {

            "user_id": request.user_id,
            "amount": request.amount,
            "recipient": request.recipient,
            "device": request.device,
            "location": request.location,
            "timestamp": request.timestamp
        },

        "risk": {

            "score": final_score,
            "level": final_level,
            "action": final_action
        },

        "behavioral_risk": {

            "score": behavioral_score,
            "level": result["risk_level"],
            "action": result["recommended_action"]
        },

        "graph_risk": graph_risk,

        "graph_connections": graph_connections,

        "signals": {

            "amount": result["amount"],
            "recipient": result["recipient"],
            "device": result["device"],
            "location": result["location"],
            "message": result["message"],
            "qr": result["qr"],
            "frequency": result["frequency"]
        },

        "explanation": {

            "strong_signal_count":
                result["strong_signal_count"],

            "base_risk":
                result["base_risk_score"],

            "interaction_bonus":
                result["interaction_bonus"],

            "behavioral_risk":
                behavioral_score,

            "graph_risk":
                graph_score,

            "combined_risk":
                final_score
        },

        "user_message": user_message
    }


# =========================================================
# GRAPH ANALYSIS
# =========================================================
# GET endpoint.
#
# Example:
# GET /graph-analysis/user_001
# =========================================================

@app.get("/graph-analysis/{user_id}")
def graph_analysis(user_id: str):

    graph = FraudGraph()

    graph.build_from_transactions(
        transactions
    )

    user_connections = graph.get_user_connections(
        user_id
    )

    user_graph_risk = graph.get_user_graph_risk(
        user_id
    )

    return {

        "user_id": user_id,

        "graph_risk": user_graph_risk,

        "connected_users": user_connections,

        "connection_summary": {

            "connected_user_count":
                user_graph_risk["connected_user_count"],

            "strong_connections":
                user_graph_risk["strong_connections"],

            "weak_connections":
                user_graph_risk["weak_connections"],

            "graph_risk_score":
                user_graph_risk["graph_risk_score"]
        },

        "message": (
            "Graph analysis identifies relationships between "
            "accounts through shared devices, recipients, "
            "and locations. These relationships are risk "
            "signals and do not by themselves prove fraud."
        )
    }


# =========================================================
# LEARN TRANSACTION
# =========================================================

@app.post("/learn")
def learn_transaction(request: LearnRequest):

    # Only approved transactions are learned
    if not request.approved:

        return {

            "status": "rejected",

            "message":
                "Transaction was not approved for behavioral learning.",

            "learned": False,

            "total_transactions":
                len(transactions)
        }

    transaction = Transaction(

        user_id=request.user_id,

        amount=request.amount,

        recipient=request.recipient,

        device=request.device,

        location=request.location,

        timestamp=request.timestamp
    )

    add_transaction(
        transactions,
        transaction
    )

    return {

        "status": "learned",

        "message":
            "Approved transaction added to behavioral history.",

        "learned": True,

        "transaction": {

            "user_id":
                transaction.user_id,

            "amount":
                transaction.amount,

            "recipient":
                transaction.recipient,

            "device":
                transaction.device,

            "location":
                transaction.location
        },

        "total_transactions":
            len(transactions)
    }
