from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from scanners.url_scanner import scan_url
from scanners.brand_scanner import scan_brand
from engine.rule_engine import apply_rules
from engine.risk_engine import calculate_risk

app = FastAPI(title="ThreatLens API")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "ThreatLens API is running"
    }


@app.get("/scan")
def scan_website(url: str):

    url_findings = scan_url(url)

    brand_findings = scan_brand(url)

    all_findings = url_findings + brand_findings

    all_findings = apply_rules(all_findings)

    result = calculate_risk(all_findings)

    result["url"] = url

    return result