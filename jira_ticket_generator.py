import pandas as pd
import numpy as np
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

class JiraTicketGenerator:
    def __init__(self, activity_report_path: str, observable_details_path: str):
        """Initialize with paths to the two CSV reports"""
        self.activity_df = pd.read_csv(activity_report_path)
        self.observable_df = pd.read_csv(observable_details_path)

    def safe_get_value(self, value: Any) -> Optional[str]:
        """Safely get a value, returning None if it's NaN, empty, or 'nan' string"""
        if pd.isna(value) or value == 'NaN' or str(value).lower() == 'nan' or value == '':
            return None
        return str(value).strip()

    def determine_gap_type(self, detection_results: Optional[str]) -> tuple[str, str]:
        """Determine if this is a detection gap, prevention gap, or both based on detection results"""
        if detection_results and detection_results.strip():
            # Detection occurred but outcome was still Failed = Prevention Gap
            return "Prevention Gap", "Security Prevention Implementation"
        else:
            # No detection occurred and outcome was Failed = Both Detection and Prevention failed
            return "Prevention and Detection Gap", "Security Detection and Prevention Implementation"

    def generate_enhanced_plain_english(self, observable_type: str, phase_name: str, 
                                      scenario_name: str, outcome: str, raw_data: Dict) -> str:
        """Generate plain English explanation without NaN values, only using available data"""

        # Base information - only include if available
        action_desc = f"The '{scenario_name}' scenario"
        outcome_desc = f"which {outcome.lower()}" if self.safe_get_value(outcome) else ""
        phase_desc = f"during the '{phase_name}' phase" if self.safe_get_value(phase_name) else ""

        # Type-specific explanations using only available data
        if observable_type == 'process':
            command_line = self.safe_get_value(raw_data.get('command_line'))
            process_args = self.safe_get_value(raw_data.get('x_process_arguments'))

            if command_line:
                if process_args:
                    return f"{action_desc} {outcome_desc} {phase_desc} executed the process '{command_line}' with arguments '{process_args}'."
                else:
                    return f"{action_desc} {outcome_desc} {phase_desc} executed the process '{command_line}'."
            else:
                return f"{action_desc} {outcome_desc} {phase_desc} executed a process."

        elif observable_type == 'file':
            file_name = self.safe_get_value(raw_data.get('name'))
            file_path = self.safe_get_value(raw_data.get('path'))
            command_line = self.safe_get_value(raw_data.get('ioc_command_line'))

            parts = []
            if file_name and file_path:
                parts.append(f"interacted with the file '{file_name}' located at '{file_path}'")
            elif file_name:
                parts.append(f"interacted with the file '{file_name}'")
            elif file_path:
                parts.append(f"interacted with a file at '{file_path}'")
            else:
                parts.append("interacted with a file")

            if command_line and file_name:
                parts.append(f"(executed via: '{command_line}')")

            return f"{action_desc} {outcome_desc} {phase_desc} {' '.join(parts)}."

        elif observable_type == 'directory':
            dir_path = self.safe_get_value(raw_data.get('path'))
            binary_path = self.safe_get_value(raw_data.get('ioc_binary_path'))

            if dir_path:
                if binary_path:
                    return f"{action_desc} {outcome_desc} {phase_desc} accessed the directory '{dir_path}' containing the binary '{binary_path}'."
                else:
                    return f"{action_desc} {outcome_desc} {phase_desc} accessed the directory '{dir_path}'."
            else:
                return f"{action_desc} {outcome_desc} {phase_desc} accessed a directory."

        elif observable_type == 'windows-registry-key':
            reg_key = self.safe_get_value(raw_data.get('key'))
            reg_values = self.safe_get_value(raw_data.get('values'))

            if reg_key:
                if reg_values:
                    return f"{action_desc} {outcome_desc} {phase_desc} modified the registry key '{reg_key}' with values '{reg_values}'."
                else:
                    return f"{action_desc} {outcome_desc} {phase_desc} modified the registry key '{reg_key}'."
            else:
                return f"{action_desc} {outcome_desc} {phase_desc} modified a registry key."

        elif observable_type == 'artifact':
            payload_bin = self.safe_get_value(raw_data.get('payload_bin'))
            md5_hash = self.safe_get_value(raw_data.get('md5'))
            binary_path = self.safe_get_value(raw_data.get('ioc_binary_path'))
            command_line = self.safe_get_value(raw_data.get('ioc_command_line'))

            if binary_path and command_line:
                return f"{action_desc} {outcome_desc} {phase_desc} created an artifact at '{binary_path}' executed with '{command_line}'."
            elif binary_path:
                return f"{action_desc} {outcome_desc} {phase_desc} created an artifact at '{binary_path}'."
            elif md5_hash:
                return f"{action_desc} {outcome_desc} {phase_desc} created an artifact (MD5: {md5_hash})."
            else:
                return f"{action_desc} {outcome_desc} {phase_desc} created an artifact as part of the attack simulation."

        else:
            return f"{action_desc} {outcome_desc} {phase_desc} performed an action of type '{observable_type}'."

    def get_observable_details_with_explanations(self, scenario_id: str) -> List[Dict]:
        """Extract observable details for a scenario with plain English explanations"""
        observables = self.observable_df[self.observable_df['scenario_id'] == scenario_id]

        if observables.empty:
            return []

        # Get scenario info for context
        scenario_info = self.activity_df[self.activity_df['Scenario ID'] == scenario_id]
        scenario_name = scenario_info.iloc[0]['Scenario Name'] if not scenario_info.empty else "Unknown Scenario"
        outcome = scenario_info.iloc[0]['Outcome'] if not scenario_info.empty else "Unknown"

        details = []
        for _, obs in observables.iterrows():
            # Prepare raw data dictionary with only non-NaN values
            raw_data = {}
            relevant_fields = [
                'command_line', 'x_command_line', 'x_process_arguments', 'name', 'path',
                'sha1', 'md5', 'sha256', 'key', 'values', 'payload_bin',
                'ioc_binary_path', 'ioc_command_line', 'ioc_alternate_data_stream_name',
                'image_ref'
            ]

            for field in relevant_fields:
                if field in obs and self.safe_get_value(obs[field]):
                    raw_data[field] = obs[field]

            # Generate plain English explanation
            plain_english = self.generate_enhanced_plain_english(
                obs['type'], obs['phase_name'], scenario_name, outcome, raw_data
            )

            detail = {
                'type': obs['type'],
                'phase_name': self.safe_get_value(obs['phase_name']),
                'prevention_outcome': self.safe_get_value(obs['prevention_outcome']),
                'detection_outcome': self.safe_get_value(obs['detection_outcome']),
                'raw_data': raw_data,
                'plain_english_explanation': plain_english
            }
            details.append(detail)

        return details

    def extract_mitre_data(self, row) -> Dict:
        """Extract and parse MITRE ATT&CK data from a row"""
        tactics = self.safe_get_value(row['MITRE Tactics'])
        techniques = self.safe_get_value(row['MITRE Techniques'])
        sub_techniques = self.safe_get_value(row['MITRE Sub-techniques'])

        # Parse comma-separated values
        tactics_list = [t.strip() for t in tactics.split(',')] if tactics else []
        techniques_list = [t.strip() for t in techniques.split(',')] if techniques else []
        sub_techniques_list = [t.strip() for t in sub_techniques.split(',')] if sub_techniques else []

        # Combine all technique IDs
        all_technique_ids = techniques_list + sub_techniques_list

        return {
            'tactics': tactics_list,
            'techniques': techniques_list,
            'sub_techniques': sub_techniques_list,
            'technique_ids': all_technique_ids
        }

    def generate_enhanced_ticket_description(self, row, observable_details: List[Dict]) -> str:
        """Generate enhanced ticket description with execution details"""
        scenario_name = self.safe_get_value(row['Scenario Name'])
        outcome = self.safe_get_value(row['Outcome'])
        outcome_desc = self.safe_get_value(row['Outcome Description'])
        detection_results = self.safe_get_value(row['Detection Results'])
        mitre_tactics = self.safe_get_value(row['MITRE Tactics'])
        mitre_techniques = self.safe_get_value(row['MITRE Techniques'])
        mitre_sub_techniques = self.safe_get_value(row['MITRE Sub-techniques'])
        hostname = self.safe_get_value(row['Asset Hostname'])
        ip_address = self.safe_get_value(row['Asset IP'])

        # Determine gap type based on detection results
        gap_type, _ = self.determine_gap_type(detection_results)

        # Determine if attack was successful (outcome is Failed)
        attack_successful = outcome and outcome.lower() == 'failed'

        description = f"h3. {gap_type}: {scenario_name}\n\n"

        if outcome:
            description += f"*Outcome:* {outcome}\n"

        # Add Attack Successful indicator
        description += f"*Attack Successful:* {'True' if attack_successful else 'False'}\n"

        if outcome_desc:
            description += f"*Outcome Description:* {outcome_desc}\n"
        if detection_results:
            description += f"*Detection Results:* {detection_results}\n"

        # Add gap-specific explanation
        if gap_type == "Prevention Gap":
            description += "\n*Gap Analysis:* The attack was detected but not prevented, indicating a gap in prevention capabilities.\n"
        elif gap_type == "Prevention and Detection Gap":
            description += "\n*Gap Analysis:* The attack was neither detected nor prevented, indicating gaps in both detection and prevention capabilities.\n"
        else:
            description += "\n*Gap Analysis:* The attack was not detected, indicating a gap in detection capabilities.\n"

        # Add execution details if available
        if observable_details:
            description += "\nh4. Execution Details\n\n"
            for i, detail in enumerate(observable_details, 1):
                if detail['plain_english_explanation']:
                    description += f"{i}. {detail['plain_english_explanation']}\n"

        # Add MITRE information if available
        if any([mitre_tactics, mitre_techniques, mitre_sub_techniques]):
            description += "\nh4. MITRE ATT&CK Information\n\n"
            if mitre_tactics:
                description += f"*Tactics:* {mitre_tactics}\n"
            if mitre_techniques:
                description += f"*Techniques:* {mitre_techniques}\n"
            if mitre_sub_techniques:
                description += f"*Sub-techniques:* {mitre_sub_techniques}\n"

        # Add asset information if available
        if hostname or ip_address:
            description += "\nh4. Affected Asset\n\n"
            if hostname:
                description += f"*Hostname:* {hostname}\n"
            if ip_address:
                description += f"*IP Address:* {ip_address}\n"

        return description

    def generate_tickets_for_failed_scenarios(self) -> Dict:
        """Generate Jira tickets for failed scenarios with enhanced details"""
        failed_scenarios = self.activity_df[self.activity_df['Outcome'] == 'Failed']

        tickets = []
        for _, row in failed_scenarios.iterrows():
            scenario_id = row['Scenario ID']
            scenario_name = self.safe_get_value(row['Scenario Name'])
            detection_results = self.safe_get_value(row['Detection Results'])
            outcome = self.safe_get_value(row['Outcome'])

            # Determine gap type and ticket type
            gap_type, ticket_type = self.determine_gap_type(detection_results)

            # Determine if attack was successful (outcome is Failed)
            attack_successful = outcome and outcome.lower() == 'failed'

            # Get observable details with explanations
            observable_details = self.get_observable_details_with_explanations(scenario_id)

            # Extract MITRE data
            mitre_data = self.extract_mitre_data(row)

            # Generate enhanced description
            description = self.generate_enhanced_ticket_description(row, observable_details)

            ticket = {
                'title': f"{gap_type}: {scenario_name}",
                'description': description,
                'type': ticket_type,
                'priority': 'High',
                'gap_type': gap_type,  # Added for clarity
                'attack_successful': attack_successful,  # New attribute
                'scenario': {
                    'id': scenario_id,
                    'name': scenario_name,
                    'type': self.safe_get_value(row['Scenario Type']),
                    'outcome': outcome,  # Keep original outcome value
                    'outcome_description': self.safe_get_value(row['Outcome Description']),
                    'detection_results': detection_results,
                    'test_name': self.safe_get_value(row['Test Name']),
                    'test_id': self.safe_get_value(row['Test ID']),
                    'run_id': self.safe_get_value(row['Run ID']),
                    'asset': {
                        'hostname': self.safe_get_value(row['Asset Hostname']),
                        'ip': self.safe_get_value(row['Asset IP']),
                        'role': self.safe_get_value(row['Asset Role']),
                        'group': self.safe_get_value(row['Asset Group'])
                    }
                },
                'mitre_data': mitre_data,
                'observables': observable_details,
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'source': 'Microsoft Defender for Endpoint Baseline Evaluation'
                }
            }
            tickets.append(ticket)

        return {'tickets': tickets}

# Example usage
if __name__ == "__main__":
    generator = JiraTicketGenerator(
        'Microsoft Defender for Endpoint Baseline for Default Policy Scenario Activity Report 2025-07-30 13_57.csv',
        'observable_details_objects_202557301357.csv'
    )

    tickets = generator.generate_tickets_for_failed_scenarios()

    # Save to JSON file
    with open('corrected_jira_tickets.json', 'w') as f:
        json.dump(tickets, f, indent=2)

    print(f"Generated {len(tickets['tickets'])} tickets for failed scenarios")
