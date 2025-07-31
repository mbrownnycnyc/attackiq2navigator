from flask import Flask, render_template, request, send_file
from parser import parse_attackiq_csvs
from jira_ticket_generator import JiraTicketGenerator
import tempfile
import os
import json

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        scenario = request.files.get("scenario")
        observable = request.files.get("observable")
        output_type = request.form.get("output_type", "navigator")

        # No server-side validation - frontend will handle it
        scenario_path = os.path.join(tempfile.gettempdir(), scenario.filename)
        observable_path = os.path.join(tempfile.gettempdir(), observable.filename)

        print(f"Reading scenario from: {scenario_path}")
        print(f"Reading observable from: {observable_path}")

        scenario.save(scenario_path)
        observable.save(observable_path)

        if output_type == "jira":
            # Generate Jira ticket JSON for failed scenarios
            # Pass the file paths to the constructor
            jira_generator = JiraTicketGenerator(scenario_path, observable_path)
            result = jira_generator.generate_tickets_for_failed_scenarios()  # Fixed method name
            output_path = os.path.join(tempfile.gettempdir(), "jira_tickets.json")
        else:
            # Generate ATT&CK Navigator layer (existing functionality)
            result = parse_attackiq_csvs(scenario_path, observable_path)
            output_path = os.path.join(tempfile.gettempdir(), "navigator_output.json")

        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)

        return send_file(output_path, as_attachment=True)

    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)
