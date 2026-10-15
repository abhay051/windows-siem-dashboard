\# Windows SIEM Dashboard



A Python-based Security Information and Event Management (SIEM) project that collects Windows Security events, stores event records in SQLite, evaluates selected security detection rules, and displays alerts through a web dashboard.



\## 1. Project Overview



This project demonstrates the core workflow of a small, local SIEM:



\- Collect Windows Security events.

\- Store event records in a SQLite database.

\- Detect selected security-related events and repeated failed logins.

\- Generate alerts with severity and risk scores.

\- Display system metrics, alerts, and event records in a Flask dashboard.

\- Support alert review and status updates.



\*\*Project type:\*\* Local security monitoring and detection prototype  

\*\*Backend:\*\* Python and Flask  

\*\*Database:\*\* SQLite  

\*\*Operating system:\*\* Windows  

\*\*Dashboard:\*\* HTML, CSS, and JavaScript



\## 2. Features



\### Windows Event Collection



The collector uses Python's Windows event-log integration to read selected events from the Windows Security log.



Collected event information includes:



\- Event ID

\- Event source

\- Event timestamp

\- Computer name

\- Event record number

\- Event message and extracted fields



Reading the Windows Security log may require running the terminal with Administrator privileges.



\### Detection Rules



The application implements detection logic for the following event types:



| Event ID | Detection | Severity | Risk score |

|---|---|---|---:|

| 4625 | Repeated failed Windows logins | High | 75 |

| 1102 | Windows Security audit log cleared | High | 85 |

| 4720 | Windows user account created | Medium | 60 |

| 4728 | Member added to a global security group | Medium | 70 |

| 4732 | Member added to a local security group | Medium | 70 |



The failed-login rule evaluates repeated failures within a five-minute window, using a threshold of five events.



Account creation and group membership alerts indicate changes that may warrant review. These events are not automatically proof of malicious activity.



\### Dashboard



The web dashboard provides a user interface for viewing security information, including:



\- System resource metrics

\- Security alerts and their severity

\- Stored Windows events

\- Event and alert filtering

\- Alert details

\- Alert status updates

\- Dashboard health information



\### SQLite Storage



SQLite provides local storage for alert records and collected Windows events.



The application database is named `siem.db`.



\## 3. Technology Stack



\- \*\*Python:\*\* Application logic and event processing

\- \*\*Flask:\*\* Web server and API endpoints

\- \*\*SQLite:\*\* Persistent local database

\- \*\*pywin32:\*\* Windows Event Log integration

\- \*\*psutil:\*\* System resource metrics

\- \*\*HTML and CSS:\*\* Dashboard structure and styling

\- \*\*JavaScript:\*\* Dashboard interactions and API requests



\## 4. Project Structure



```text

SIEM-Project/

├── app.py

├── windows\_logs.py

├── siem.db

├── test\_detection.py

├── test\_end\_to\_end.py

├── templates/

│   └── index.html

├── static/

│   ├── css/

│   │   └── style.css

│   └── js/

│       └── dashboard.js

└── venv/

```



The folder also contains isolated test databases created during development. These are test artifacts and are not required to understand the main application architecture.



\## 5. Installation and Setup



\### Prerequisites



\- Windows

\- Python 3.12 or a compatible Python version

\- Access to the Windows Security event log

\- Administrator privileges where required



\### Step 1: Open the project directory



```cmd

cd C:\\SIEM-Project

```



\### Step 2: Activate the virtual environment



```cmd

venv\\Scripts\\activate

```



\### Step 3: Install dependencies if needed



The project uses Flask, psutil, python-dotenv, requests, and pywin32. Install any missing dependencies with:



```cmd

python -m pip install flask psutil python-dotenv requests pywin32

```



\### Step 4: Start the application



Run the application using the project's Python environment:



```cmd

python app.py

```



If Windows Security log access fails, close the terminal and reopen Command Prompt as Administrator before starting the application again.



\### Step 5: Open the dashboard



Visit:



http://127.0.0.1:5000/



The dashboard is intended for local use. Do not expose the development server directly to the public internet.



\## 6. API Endpoints



The application includes the following endpoints:



| Endpoint | Purpose |

|---|---|

| `/api/metrics` | System metrics |

| `/api/alerts` | Alert records |

| `/api/alerts/<id>/status` | Update an alert's status |

| `/api/health` | Application health information |

| `/api/windows-events` | Read and store Windows events |

| `/api/windows-events/stored` | Retrieve stored Windows events |



These endpoints are part of the local application's API. Their exact response formats are defined by the implementation.



\## 7. Testing



The project includes two synthetic detection test scripts:



\- `test\_detection.py`

\- `test\_end\_to\_end.py`



The detection test suite passed all five checks:



1\. Repeated failed logins (4625)

2\. Security log cleared (1102)

3\. User account creation (4720)

4\. Global security group membership change (4728)

5\. Local security group membership change (4732)



The isolated end-to-end test suite also passed all five checks.



\*\*Recorded test result:\*\* 5/5 checks passed in each suite.



The tests used separate test databases rather than the production `siem.db`. These results verify the tested synthetic scenarios; they do not establish complete detection coverage against all real Windows events.



To run the test scripts, activate the virtual environment and execute:



```cmd

python test\_detection.py

```



```cmd

python test\_end\_to\_end.py

```



The scripts intentionally stop if their designated test databases already exist. Use a new test database filename before rerunning them; do not delete production data to reset a test.



\## 8. Security Considerations and Limitations



\- Windows Security log access may require elevated privileges.

\- The current rules cover a limited set of event types.

\- Synthetic tests do not replace validation against real Windows event records.

\- Event field positions and message formats can vary by Windows event type and version.

\- The application is a local prototype, not a hardened enterprise SIEM.

\- Authentication, role-based access control, secure remote deployment, and production-grade audit protection should be evaluated before broader use.

\- A cleared Security log may reduce available forensic evidence, so the alert should be investigated promptly.

\- Alerts should be treated as investigation signals rather than definitive proof of compromise.



\## 9. Future Improvements



Potential next steps include:



\- Add process-creation detection for Event ID 4688.

\- Parse event fields into named attributes for better alert details.

\- Add detection rules for additional authentication and privilege-related events.

\- Add severity filters, search, and alert acknowledgements.

\- Improve error handling and structured logging.

\- Add automated tests for API responses and database persistence.

\- Add dependency pinning through a `requirements.txt` file.

\- Add screenshots, architecture diagrams, and sample alert investigations.

\- Improve authentication and security controls before considering remote deployment.



\## 10. Learning Outcomes



This project provides practical experience with:



\- Windows event monitoring

\- Security detection rules

\- Python backend development

\- Flask APIs

\- SQLite persistence

\- Dashboard development

\- Synthetic testing

\- Basic SIEM architecture and alert triage



\## License



Choose and add an appropriate open-source license before publishing this project publicly.



