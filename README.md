# 🚍 AttackIQ CSV Processor 📊

![Image](https://github.com/user-attachments/assets/e9ec552c-2bc5-4396-ba62-68e90c246df9)

## Project Overview

This tool processes AttackIQ security validation data and maps it to the MITRE ATT&CK framework. It provides two main functionalities:

1. **ATT&CK Navigator Layer Generation**: Creates visualizations for security coverage based on test results
2. **Jira Ticket Creation**: Automatically generates structured Jira tickets for failed security tests

## Demo site

* [Demo](https://mbrownnycnyc.github.io/attackiq2navigator_site) based on [dfe7e31ba2b3e7fb607b4d2d20e73ce7a8584e68](https://github.com/mbrownnycnyc/attackiq2navigator/commit/dfe7e31ba2b3e7fb607b4d2d20e73ce7a8584e68).


## 💠 Quick Setup

### 🧧 Bash/Linux Setup

```bash
# Install Python dependencies
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run the application
python app.py
```

### 🧢 PowerShell Setup

```powershell
# Install Python if needed (via winget)
winget install Python.Python.3.13

# Create and activate virtual environment
python -m venv venv
. .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

## 🧩 Project Components

- **app.py**: Flask web application entry point
- **parser.py**: Processes CSV data and creates ATT&CK Navigator layers
- **jira_ticket_generator.py**: Creates structured Jira tickets for failed tests
- **upload.html**: Web interface for file uploads and configuration
- **requirements.txt**: Project dependencies

## 🔤 Dependencies

- **Flask**: Web framework for the application interface
- **Pandas**: Data processing and CSV parsing

## 🔐 How It Works

1. Upload AttackIQ CSV files (Scenario Activity Report and Observable Details)
2. Select output type (Navigator Layer or Jira Tickets)
3. Process button generates the selected output format
4. Download the resulting JSON file for use in MITRE ATT&CK Navigator or Jira

## 🔷 Making It Production-Ready

### 🎾 Production Considerations

1. **Secure the Application**:
   - Add authentication for the web interface
   - Implement HTTPS with proper certificates
   - Add input validation for all file uploads

2. **Improve Error Handling**:
   - Create comprehensive error handlers for file parsing issues
   - Add logging to track application behavior
   - Implement better exception management

3. **Deployment Options**:
   - **Docker Containerization**:
     ```bash
     # Create a Dockerfile with Python, dependencies and app code
     # Build and deploy with proper resource limits
     ```
   - **WSGI Server**:
     ```bash
     # Install Gunicorn or uWSGI
     pip install gunicorn
     gunicorn -w 4 -b 0.0.0.0:8000 app:app
     ```
   - **Reverse Proxy**:
     ```
     # Configure Nginx/Apache in front of the application
     # for better performance and security
     ```

4. **Performance Optimization**:
   - Add caching for processed results
   - Optimize CSV parsing for large files
   - Implement background processing for large datasets

### 📘 Code Improvements

1. **Refactoring**:
   - Create a proper module structure
   - Separate configuration from application code
   - Implement proper testing

2. **Feature Enhancements**:
   - Add more output formats
   - Implement persistent storage for results
   - Create dashboard for historical results

## 📈 Usage Examples

### ATT&CK Navigator Layer Generation

Upload AttackIQ CSV files and select the "MITRE ATT&CK Navigator Layer" option to generate a heatmap of your security coverage that can be loaded into the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

### Jira Ticket Generation

Upload AttackIQ CSV files and select the "Jira Tickets for Failed Tests" option to create structured JSON data that can be imported into Jira for security improvement tracking.

## 🔩 Contributing

Contributions welcome! Please feel free to submit a Pull Request.