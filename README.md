\# Security Orchestration, Automation and Response (SOAR)



\## Internship Details

\- \*\*Intern ID:\*\* CITS9336

\- \*\*Full Name:\*\* KAMANI SREEJA

\- \*\*Internship Duration:\*\* 6 WEEKS

\- \*\*Project Number:\*\* 29



\## Project Scope

This project implements a prototype SOAR dashboard for managing simulated security alerts, assigning severity levels, tracking incidents, recommending responses, and recording audit events.



\## Features

\- Security alert creation

\- Automatic severity classification

\- Incident register and status tracking

\- Response recommendations

\- Incident resolution workflow

\- Audit event logging

\- Web-based security dashboard

\- Health-check API endpoint



\## Technologies

\- Python

\- Flask

\- HTML

\- CSS

\- JavaScript

\- REST APIs



\## Project Structure

```text

SOAR\_Implementation/

├── app.py

├── requirements.txt

├── README.md

└── screenshots/

&#x20;   └── soar\_dashboard.png

```



\## Installation

Create and activate a virtual environment:



`python -m venv venv`



Windows:



`venv\\Scripts\\activate`



Install dependencies:



`pip install -r requirements.txt`



\## Execution

Start the application:



`python app.py`



Open the dashboard at:



`http://127.0.0.1:5001`



Health endpoint:



`http://127.0.0.1:5001/api/health`



Audit endpoint:



`http://127.0.0.1:5001/api/audit`



\## Testing

The dashboard was tested with simulated failed-login and file-integrity alerts. Automatic severity classification, incident resolution, dashboard metrics, and audit event recording were verified.



\## Limitations

Incident and audit data are stored in memory and are lost when the server restarts. Responses are recommendations only; the application does not block accounts, terminate processes, or modify real systems. Authentication and persistent database storage are not implemented.



\## Ethical Use

This project is intended for educational cybersecurity research and defensive incident-response learning.

