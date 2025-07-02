import pandas as pd
import json
import os

def safe_read_csv(path):
    try:
        return pd.read_csv(path, encoding='utf-8')
    except UnicodeDecodeError:
        return pd.read_csv(path, encoding='utf-16')

def parse_attackiq_csvs(scenario_path, observable_path):
    # Load CSV files
    scenario_data = safe_read_csv(scenario_path)
    observable_data = safe_read_csv(observable_path)
    
    # Create tracking map for techniques
    technique_tracker = {}  # techniqueID -> {passed: count, total: count, comments: []}
    
    # Process each scenario in the scenario data
    for _, row in scenario_data.iterrows():
        # Extract MITRE techniques (both from Techniques and Sub-techniques columns)
        techniques_str = str(row.get("MITRE Techniques", ""))
        sub_techniques_str = str(row.get("MITRE Sub-techniques", ""))
        
        # Combine and split techniques into a list
        all_techniques = []
        if techniques_str and techniques_str.lower() != 'nan':
            all_techniques.extend([t.strip() for t in techniques_str.split(',')])
        if sub_techniques_str and sub_techniques_str.lower() != 'nan':
            all_techniques.extend([t.strip() for t in sub_techniques_str.split(',')])
        
        # Skip if no techniques found
        if not all_techniques:
            continue
        
        # Get scenario outcome
        outcome = str(row.get("Outcome", "")).strip()
        is_passed = outcome == "Passed"
        
        # Create comment with scenario details
        scenario_name = row.get("Scenario Name", "")
        scenario_id = row.get("Scenario ID", "")
        detection_results = row.get("Detection Results", "")
        
        # Find prevention_outcome and detection_outcome from observable data
        prevention_outcome = ""
        detection_outcome = ""
        matching_observables = observable_data[observable_data['scenario_id'] == scenario_id]
        if not matching_observables.empty:
            prevention_outcome = matching_observables['prevention_outcome'].iloc[0] if 'prevention_outcome' in matching_observables.columns else ""
            detection_outcome = matching_observables['detection_outcome'].iloc[0] if 'detection_outcome' in matching_observables.columns else ""
        
        comment = f"scenario name: {scenario_name}, detection results: {scenario_id}"
        comment += f", prevention outcomes: {prevention_outcome}, detection outcomes: {detection_outcome}"
        
        # Update technique tracker
        for technique in all_techniques:
            # Skip empty technique IDs
            if not technique or technique.lower() == 'nan':
                continue
            
            if technique not in technique_tracker:
                technique_tracker[technique] = {
                    'passed': 0, 
                    'total': 0,
                    'comments': []
                }
            
            technique_tracker[technique]['total'] += 1
            if is_passed:
                technique_tracker[technique]['passed'] += 1
            technique_tracker[technique]['comments'].append(f"{comment} (Outcome: {outcome})")
    
    # Calculate scores based on success rate
    score_map = {}
    for technique, data in technique_tracker.items():
        if data['total'] == 0:
            continue
            
        # Calculate success rate and convert to integer score (0-100)
        success_rate = data['passed'] / data['total']
        score = int(success_rate * 100)
        
        # Combine comments, but limit to avoid excessive length
        combined_comments = "; ".join(data['comments'][:3])
        if len(data['comments']) > 3:
            combined_comments += f"; and {len(data['comments']) - 3} more instances"
            
        score_map[technique] = {
            "score": score,
            "comment": f"Success rate: {data['passed']}/{data['total']} = {score}%. {combined_comments}"
        }
    
    # Load empty layer template
    try:
        with open("navigator_empty_layer.json", "r", encoding="utf-8") as f:
            base_layer = json.load(f)
    except Exception as e:
        # Create minimal navigator layer if template can't be loaded
        base_layer = {
            "name": "AttackIQ Evaluation",
            "versions": {
                "attack": "14",
                "navigator": "4.8.0",
                "layer": "4.4"
            },
            "domain": "enterprise-attack",
            "description": "Layer showing results from AttackIQ evaluation with success rate scoring",
            "techniques": [],
            "legendItems": [
                {
                    "label": "0% Success (No Defense)",
                    "color": "#ff0000"
                },
                {
                    "label": "50% Success (Partial Defense)",
                    "color": "#ffff00"
                },
                {
                    "label": "100% Success (Full Defense)",
                    "color": "#00ff00"
                }
            ]
        }
    
    # Populate techniques based on score_map
    base_layer["techniques"] = []
    for tid, info in score_map.items():
        # Generate color gradient from red (0%) to yellow (50%) to green (100%)
        score_pct = info["score"] / 100
        if score_pct <= 0.5:
            # Red to Yellow gradient (0% to 50%)
            r = 255
            g = int(255 * (score_pct * 2))
            b = 0
        else:
            # Yellow to Green gradient (50% to 100%)
            r = int(255 * (1 - (score_pct - 0.5) * 2))
            g = 255
            b = 0
        
        color = f"#{r:02x}{g:02x}{b:02x}"
        
        technique = {
            "techniqueID": tid,
            "score": info["score"],
            "comment": info["comment"],
            "enabled": True,
            "color": color
        }
        base_layer["techniques"].append(technique)
    
    return base_layer