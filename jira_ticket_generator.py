import pandas as pd
import json
import logging
import re
import os
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class JiraTicketGenerator:
    """
    Generates structured Jira ticket data from AttackIQ security test results
    """
    
    def __init__(self):
        # Initialize technique recommendations mapping
        self.technique_recommendations = self._load_technique_recommendations()
    
    def _load_technique_recommendations(self):
        """
        Load technique recommendations from the JSON file.

        Returns:
            dict: A dictionary mapping technique IDs to their detection and prevention methods.
        """
        recommendations = {}
        current_dir = os.path.dirname(os.path.abspath(__file__))
        json_file_path = os.path.join(current_dir, 'mitre_techniques_data_summary.json')

        try:
            with open(json_file_path, 'r', encoding='utf-8') as f:
                techniques_data = json.load(f)

            # The JSON is structured as a dictionary with technique IDs as keys
            for technique_id, technique_data in techniques_data.items():
                if not technique_id:
                    continue
                
                # Extract detection descriptions
                detection = []
                
                # Get detections from the detections array
                if 'detections' in technique_data and technique_data['detections']:
                    for detect_item in technique_data['detections']:
                        if 'description' in detect_item and detect_item['description']:
                            detection.append(detect_item['description'])
                
                # If no specific detections found, try the generic_detection field
                if not detection and 'generic_detection' in technique_data and technique_data['generic_detection']:
                    detection.append(technique_data['generic_detection'])
                
                # If still no detections, add a generic one
                if not detection:
                    detection = ["Monitor for suspicious activity related to this technique."]
                
                # Extract prevention descriptions from mitigations
                prevention = []
                if 'mitigations' in technique_data and technique_data['mitigations']:
                    for mitigation in technique_data['mitigations']:
                        if 'description' in mitigation and mitigation['description']:
                            prevention.append(mitigation['description'])
                
                # If no specific preventions, add a generic one
                if not prevention:
                    prevention = ["Implement security controls to prevent this technique."]
                
                # Store recommendations
                recommendations[technique_id] = {
                    "detection": detection,
                    "prevention": prevention
                }

            logger.info(f"Loaded recommendations for {len(recommendations)} techniques")
            return recommendations
        
        except Exception as e:
            logger.error(f"Error loading technique recommendations: {str(e)}")
            # Return a minimal default dictionary if loading fails
            return {
                "T1059": {
                    "detection": ["Monitor for suspicious command-line activities."],
                    "prevention": ["Implement application control solutions."]
                }
            }
    
    def safe_read_csv(self, path):
        """Safely read CSV files with appropriate encoding"""
        try:
            return pd.read_csv(path, encoding='utf-8')
        except UnicodeDecodeError:
            return pd.read_csv(path, encoding='utf-16')
    
    def generate_tickets(self, scenario_path, observable_path):
        """Generate Jira tickets for failed security tests"""
        try:
            # Load CSV files
            logger.info(f"Loading scenario data from {scenario_path}")
            scenario_data = self.safe_read_csv(scenario_path)
            
            logger.info(f"Loading observable data from {observable_path}")
            observable_data = self.safe_read_csv(observable_path)
            
            # Filter for failed scenarios
            failed_scenarios = scenario_data[scenario_data['Outcome'] != 'Passed']
            
            if failed_scenarios.empty:
                logger.info("No failed scenarios found")
                return []
            
            logger.info(f"Found {len(failed_scenarios)} failed scenarios")
            
            # Generate tickets for each failed scenario
            tickets = []
            for _, scenario in failed_scenarios.iterrows():
                try:
                    ticket = self._generate_ticket(scenario, observable_data)
                    tickets.append(ticket)
                except Exception as e:
                    logger.error(f"Error generating ticket for scenario {scenario.get('Scenario ID', 'unknown')}: {str(e)}")
            
            return tickets
        
        except Exception as e:
            logger.error(f"Error generating tickets: {str(e)}")
            raise
    
    def _generate_ticket(self, scenario, observable_data):
        """Generate a structured ticket for a failed scenario"""
        scenario_id = scenario.get('Scenario ID', '')
        scenario_name = scenario.get('Scenario Name', '')
        
        # Find observables related to this scenario
        scenario_observables = observable_data[observable_data['scenario_id'] == scenario_id]
        
        # Extract MITRE techniques
        techniques = self._extract_techniques(scenario)
        
        # Create recommendations based on MITRE techniques
        recommendations = self._generate_recommendations(techniques)
        
        # Extract scenario details
        scenario_details = self._extract_scenario_details(scenario)
        
        # Extract observable details
        observable_details = self._extract_observable_details(scenario_observables)
        
        # Create ticket structure
        ticket = {
            "title": f"Detection Gap: {scenario_name}",
            "description": self._generate_description(scenario),
            "type": "Security Detection Implementation",
            "priority": "High",
            "scenario": scenario_details,
            "mitre_data": techniques,
            "observables": observable_details,
            "recommendations": recommendations,
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "source": "Cortex XDR Baseline Evaluation"
            }
        }
        
        return ticket
    
    def _extract_techniques(self, scenario):
        """Extract MITRE ATT&CK techniques from the scenario"""
        techniques_str = str(scenario.get("MITRE Techniques", ""))
        sub_techniques_str = str(scenario.get("MITRE Sub-techniques", ""))
        tactics_str = str(scenario.get("MITRE Tactics", ""))
        
        # Parse into lists
        techniques = []
        if techniques_str and techniques_str.lower() != 'nan':
            techniques = [t.strip() for t in techniques_str.split(',') if t.strip()]
        
        sub_techniques = []
        if sub_techniques_str and sub_techniques_str.lower() != 'nan':
            sub_techniques = [t.strip() for t in sub_techniques_str.split(',') if t.strip()]
        
        tactics = []
        if tactics_str and tactics_str.lower() != 'nan':
            tactics = [t.strip() for t in tactics_str.split(',') if t.strip()]
        
        # Extract technique IDs for easier reference
        technique_ids = [self._extract_technique_id(t) for t in techniques + sub_techniques]
        
        return {
            "tactics": tactics,
            "techniques": techniques,
            "sub_techniques": sub_techniques,
            "technique_ids": technique_ids
        }
    
    def _extract_technique_id(self, technique_string):
        """Extract technique ID from technique string (e.g., 'T1059 Command and...' -> 'T1059')"""
        if not technique_string:
            return ""
        
        match = re.search(r'(T\d{4}(?:\.\d{3})?)', technique_string)
        return match.group(1) if match else technique_string
    
    def _extract_scenario_details(self, scenario):
        """Extract relevant details from a scenario"""
        return {
            "id": scenario.get("Scenario ID", ""),
            "name": scenario.get("Scenario Name", ""),
            "type": scenario.get("Scenario Type", ""),
            "outcome": scenario.get("Outcome", ""),
            "outcome_description": scenario.get("Outcome Description", ""),
            "detection_results": scenario.get("Detection Results", ""),
            "test_name": scenario.get("Test Name", ""),
            "test_id": scenario.get("Test ID", ""),
            "run_id": scenario.get("Run ID", ""),
            "asset": {
                "hostname": scenario.get("Asset Hostname", ""),
                "ip": scenario.get("Asset IP", ""),
                "role": scenario.get("Asset Role", ""),
                "group": scenario.get("Asset Group", "")
            }
        }
    
    def _extract_observable_details(self, observables):
        """Extract relevant details from observables"""
        if observables.empty:
            return []
        
        observable_details = []
        
        for _, observable in observables.iterrows():
            # Create a dictionary for each observable
            obs = {}
            
            # Map important fields to check in the observable data
            field_mappings = {
                "name": ["name", "ioc_name"],
                "type": ["type"],
                "path": ["path", "ioc_path"],
                "command_line": ["command_line", "x_command_line", "ioc_command line"],
                "hash_md5": ["md5"],
                "hash_sha256": ["ioc_sha-256"],
                "user": ["user", "ioc_user"],
                "domain": ["domain", "ioc_domain"]
            }
            
            # Extract fields using the mappings
            for target_field, source_fields in field_mappings.items():
                for field in source_fields:
                    if field in observable and pd.notna(observable[field]):
                        obs[target_field] = observable[field]
                        break
            
            if obs:  # Only add if we have data
                observable_details.append(obs)
        
        return observable_details
    
    def _generate_recommendations(self, mitre_data):
        """Generate structured detection and prevention recommendations based on MITRE techniques"""
        recommendations_by_technique = {}
        
        # Get unique technique IDs
        technique_ids = mitre_data.get("technique_ids", [])
        
        # For each technique, create a structured recommendation entry
        for technique_id in technique_ids:
            # Get base technique ID without sub-technique
            base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
            
            # Create entries for both the specific technique and base technique
            for id_to_use in [technique_id, base_id]:
                if id_to_use in self.technique_recommendations:
                    rec = self.technique_recommendations[id_to_use]
                    
                    # Add structured recommendations
                    if id_to_use not in recommendations_by_technique:
                        recommendations_by_technique[id_to_use] = {
                            "technique_id": id_to_use,
                            "name": id_to_use,  # Can be enhanced with technique name lookup
                            "detection": rec["detection"],
                            "prevention": rec["prevention"]
                        }
        
        return {
            "by_technique": list(recommendations_by_technique.values()),
            "summary": {
                "detection": self._summarize_recommendations([r["detection"] for r in recommendations_by_technique.values()]),
                "prevention": self._summarize_recommendations([r["prevention"] for r in recommendations_by_technique.values()])
            }
        }

    def _summarize_recommendations(self, recommendation_lists):
        """Create a summarized, deduplicated list of recommendations"""
        # Implement more sophisticated deduplication logic here
        # This could use fuzzy matching or other NLP techniques
        all_recommendations = [item for sublist in recommendation_lists for item in sublist]
        # Basic deduplication for now
        return list(set(all_recommendations))
    
    def _generate_description(self, scenario):
        """Generate a detailed description for the Jira ticket"""
        scenario_name = scenario.get("Scenario Name", "")
        outcome = scenario.get("Outcome", "")
        outcome_desc = scenario.get("Outcome Description", "")
        detection_results = scenario.get("Detection Results", "")
        
        # Extract tactics and techniques
        tactics_str = str(scenario.get("MITRE Tactics", ""))
        techniques_str = str(scenario.get("MITRE Techniques", ""))
        sub_techniques_str = str(scenario.get("MITRE Sub-techniques", ""))
        
        tactics = [t.strip() for t in tactics_str.split(',') if t.strip() and t.lower() != 'nan']
        techniques = [t.strip() for t in techniques_str.split(',') if t.strip() and t.lower() != 'nan']
        sub_techniques = [t.strip() for t in sub_techniques_str.split(',') if t.strip() and t.lower() != 'nan']
        
        # Build description
        description = f"h3. Detection Gap: {scenario_name}\n\n"
        description += f"*Outcome:* {outcome}\n"
        if outcome_desc and str(outcome_desc).lower() != 'nan':
            description += f"*Outcome Description:* {outcome_desc}\n"
        if detection_results and str(detection_results).lower() != 'nan':
            description += f"*Detection Results:* {detection_results}\n"
        
        description += "\nh4. MITRE ATT&CK Information\n\n"
        if tactics:
            description += f"*Tactics:* {', '.join(tactics)}\n"
        if techniques:
            description += f"*Techniques:* {', '.join(techniques)}\n"
        if sub_techniques:
            description += f"*Sub-techniques:* {', '.join(sub_techniques)}\n"
        
        # Add asset information
        asset_hostname = scenario.get("Asset Hostname", "")
        asset_ip = scenario.get("Asset IP", "")
        
        if asset_hostname or asset_ip:
            description += "\nh4. Affected Asset\n\n"
            if asset_hostname and str(asset_hostname).lower() != 'nan':
                description += f"*Hostname:* {asset_hostname}\n"
            if asset_ip and str(asset_ip).lower() != 'nan':
                description += f"*IP Address:* {asset_ip}\n"
        
        return description