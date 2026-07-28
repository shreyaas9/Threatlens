# ThreatLens

ThreatLens is a rule-based Website Risk & Phishing Detection Platform that analyzes URLs for potential phishing indicators and assigns a risk score with an explanation.

## Features

- URL security analysis
- Brand impersonation detection
- Typosquatting detection
- Suspicious keyword detection
- Rule-based phishing detection
- Explainable risk scoring
- REST API built with FastAPI

## Tech Stack

- Python
- FastAPI
- HTML
- CSS
- JavaScript

## Project Structure

```
ThreatLens/
│
├── backend/
│   ├── engine/
│   ├── intelligence/
│   ├── scanners/
│   ├── main.py
│   └── requirements.txt
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── script.js
```

## Installation

```bash
git clone https://github.com/shreyaas9/Threatlens.git

cd Threatlens/backend

pip install -r requirements.txt

uvicorn main:app --reload
```

The API will be available at:

```
http://127.0.0.1:8000
```

Swagger documentation:

```
http://127.0.0.1:8000/docs
```

## Future Improvements

- SSL Certificate Analysis
- DNS Intelligence
- WHOIS Analysis
- Content Scanner
- Threat Intelligence Integration
- Machine Learning Risk Model

## Author
Shreyaas