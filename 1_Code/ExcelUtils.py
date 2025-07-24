import os
import json
import pandas as pd
from typing import List, Dict, Any
import logging
import xlsxwriter

logger = logging.getLogger(__name__)

class ExcelWriter:
    def __init__(self, output_dir: str):
        """
        Initialize Excel writer
        Args:
            output_dir: Directory to save Excel files
        """
        self.output_dir = output_dir
        self.total_methods_analyzed = 0
        self.total_malicious_methods = 0
        self.total_apks = 0
        os.makedirs(output_dir, exist_ok=True)

    def write_results(self, apk_hash: str, behavior_id: int, results: List[Dict[str, Any]], llm_names: List[str], total_methods_count: int):
        """
        Write analysis results to Excel file and save full method content to text files when necessary
        Args:
            apk_hash: Hash of the APK file
            behavior_id: ID of the behavior analyzed
            results: List of results to write
            llm_names: List of LLM names used in analysis
            total_methods_count: Total number of methods analyzed
        """
        if not results:
            return

        # Update counters
        self.total_methods_analyzed += total_methods_count
        self.total_malicious_methods += len(results)
        self.total_apks += 1

        # Calculate per-LLM statistics and overlaps
        llm_stats = {llm: 0 for llm in llm_names}
        overlap_count = 0
        for result in results:
            malicious_llms = []
            for llm_name in llm_names:
                if result.get('llmResults', {}).get(llm_name, {}).get('is_malicious', False):
                    llm_stats[llm_name] += 1
                    malicious_llms.append(llm_name)
            if len(malicious_llms) > 1:
                overlap_count += 1

        # Create directories
        behavior_dir = os.path.join(self.output_dir, f"behavior_{behavior_id}")
        app_dir = os.path.join(behavior_dir, apk_hash)
        os.makedirs(app_dir, exist_ok=True)

        # Create methods directory for content that won't fit in Excel
        methods_dir = os.path.join(app_dir, "methods")
        os.makedirs(methods_dir, exist_ok=True)

        # Maximum size for inline content (in characters)
        MAX_INLINE_CONTENT_SIZE = 5000

        # Prepare data for DataFrame
        columns = ['Class Name', 'Method Signature', 'Fully Qualified Name', 'Method Content', 'Method Content File', 'Review (Y/P/N)', 'Notes']
        columns.extend(llm_names)
        data = []

        for idx, result in enumerate(results):
            # Create fully qualified name
            fully_qualified_name = f"L{result['className']};->{result['methodSignature'].split()[2]}"

            # Get simplified content
            simplified_content = result.get('simplifiedContent', '')

            # Determine if external file is needed
            needs_external_file = len(simplified_content) > MAX_INLINE_CONTENT_SIZE
            method_file_path = ""

            if needs_external_file:
                # Save full method content to file
                method_file = os.path.join(methods_dir, f"method_{idx+1}.smali")
                with open(method_file, 'w', encoding='utf-8') as f:
                    f.write(result['methodContent'])
                method_file_path = os.path.relpath(method_file, self.output_dir)

            # Determine what to put in Excel cell
            content_for_excel = (
                f"[Content too large - See file: {method_file_path}]"
                if needs_external_file
                else simplified_content
            )

            row = {
                'Class Name': result['className'],
                'Method Signature': result['methodSignature'],
                'Fully Qualified Name': fully_qualified_name,
                'Method Content': content_for_excel,
                'Method Content File': method_file_path,
                'Review (Y/P/N)': '',
                'Notes': ''
            }

            # Add LLM results
            for llm_name in llm_names:
                llm_result = result.get('llmResults', {}).get(llm_name, {})
                is_malicious = llm_result.get('is_malicious', False)
                explanation = llm_result.get('explanation', 'N/A')

                # Check if explanation needs external file
                if len(explanation) > MAX_INLINE_CONTENT_SIZE:
                    explanation_file = os.path.join(methods_dir, f"method_{idx+1}_{llm_name}_explanation.txt")
                    with open(explanation_file, 'w', encoding='utf-8') as f:
                        f.write(explanation)
                    explanation_for_excel = f"[Explanation too large - See file: {os.path.relpath(explanation_file, self.output_dir)}]"
                else:
                    explanation_for_excel = explanation

                row[llm_name] = f"{'YES' if is_malicious else 'NO'}: {explanation_for_excel}"

            data.append(row)

        # Create DataFrame and save to Excel
        df = pd.DataFrame(data, columns=columns)
        excel_file = os.path.join(app_dir, f"{apk_hash}_behavior_{behavior_id}_results.xlsx")
        
        with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Results', index=False)

            # Add summary sheet with enhanced statistics
            summary_data = {
                'APK Hash': [apk_hash],
                'Behavior ID': [behavior_id],
                'Total Methods Analyzed': [total_methods_count],
                'Total Malicious Methods Found': [len(results)],
                'Detection Rate': [f"{(len(results)/total_methods_count*100):.2f}%"],
                'Methods with External Files': [sum(1 for row in data if row['Method Content File'])],
                'Overlapping Detections': [overlap_count]
            }
            
            # Add per-LLM statistics
            for llm_name, count in llm_stats.items():
                summary_data[f'{llm_name} Detections'] = [count]
                summary_data[f'{llm_name} Detection Rate'] = [f"{(count/total_methods_count*100):.2f}%"]
            
            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)

    def write_summary(self):
        """Write summary statistics to the summary sheet"""
        summary_data = {
            'Total APKs Analyzed': [self.total_apks],
            'Total Behaviors Analyzed': [self.total_behaviors],
            'Total Classes Analyzed': [self.total_classes_analyzed],
            'Total Methods Analyzed': [self.total_methods_analyzed],
            'Total Malicious Classes': [self.total_malicious_classes],
            'Total Malicious Methods': [self.total_malicious_methods],
            'Overall Detection Rate': [f"{(self.total_malicious_methods/self.total_methods_analyzed*100):.2f}%" if self.total_methods_analyzed > 0 else "0.00%"],
            'Average Processing Time (seconds)': [f"{self.total_processing_time/self.total_apks:.2f}" if self.total_apks > 0 else "0.00"]
        }
        
        # Convert to DataFrame and write to Excel
        summary_df = pd.DataFrame(summary_data)
        summary_file = os.path.join(self.output_dir, "analysis_summary.xlsx")
        summary_df.to_excel(summary_file, index=False)

    def write_progressive_results(
        self,
        apk_hash: str,
        behavior_id: int,
        results: List[Dict[str, Any]],
        llm_names: List[str],
        total_classes: int
    ) -> None:
        """
        Write progressive analysis results to Excel
        Args:
            apk_hash: Hash of the APK file
            behavior_id: ID of the behavior analyzed
            results: List of analysis results
            llm_names: List of LLM names used
            total_classes: Total number of classes analyzed
        """
        try:
            # Create behavior directory
            behavior_dir = os.path.join(self.output_dir, f"behavior_{behavior_id}")
            app_dir = os.path.join(behavior_dir, apk_hash)
            os.makedirs(app_dir, exist_ok=True)
            
            # Create Excel file
            excel_file = os.path.join(app_dir, f"{apk_hash}_behavior_{behavior_id}_results.xlsx")
            workbook = xlsxwriter.Workbook(excel_file)
            
            # Add summary sheet
            summary_sheet = workbook.add_worksheet("Summary")
            summary_sheet.write(0, 0, "Total Classes Analyzed")
            summary_sheet.write(0, 1, total_classes)
            summary_sheet.write(1, 0, "Malicious Classes Found")
            summary_sheet.write(1, 1, len(results))
            
            # Add detailed results sheet
            results_sheet = workbook.add_worksheet("Detailed Results")
            
            # Write headers
            headers = [
                "Class Name",
                "LLM Name",
                "Stage 1: Decision",
                "Stage 1: Confidence",
                "Stage 1: Explanation",
                "Stage 2: Involved Methods",
                "Stage 2: Methods Confidence",
                "Stage 2: Methods Role",
                "Stage 2: Explanation"
            ]
            for i, header in enumerate(headers):
                results_sheet.write(0, i, header)
            
            wrap_format = workbook.add_format({'text_wrap': True, 'valign': 'top'})
            row = 1
            for result in results:
                class_name = result["className"]
                for llm_name in llm_names:
                    stage1 = result["stage1_results"].get(llm_name, {})
                    stage2 = result["stage2_results"].get(llm_name, {})
                    # Stage 1 fields
                    decision = "YES" if stage1.get("is_malicious") else "NO"
                    confidence = stage1.get("confidence", "")
                    explanation = stage1.get("explanation", "")
                    # Stage 2 fields
                    methods = stage2.get("involved_methods", [])
                    methods_signatures = "\n".join([m.get("method_signature", "") for m in methods]) if methods else ""
                    methods_confidence = "\n".join([str(m.get("confidence", "")) for m in methods]) if methods else ""
                    methods_role = "\n".join([m.get("role", "") for m in methods]) if methods else ""
                    stage2_explanation = stage2.get("explanation", "")
                    # Write row
                    results_sheet.write(row, 0, class_name)
                    results_sheet.write(row, 1, llm_name)
                    results_sheet.write(row, 2, decision)
                    results_sheet.write(row, 3, confidence)
                    results_sheet.write(row, 4, explanation, wrap_format)
                    results_sheet.write(row, 5, methods_signatures, wrap_format)
                    results_sheet.write(row, 6, methods_confidence, wrap_format)
                    results_sheet.write(row, 7, methods_role, wrap_format)
                    results_sheet.write(row, 8, stage2_explanation, wrap_format)
                    row += 1
            # Adjust column widths
            results_sheet.set_column(0, 1, 30)  # Class Name, LLM Name
            results_sheet.set_column(2, 3, 15)  # Decision, Confidence
            results_sheet.set_column(4, 8, 40, wrap_format)  # Explanations and methods
            workbook.close()
            logger.info(f"Successfully wrote results to {excel_file}")
            
        except Exception as e:
            logger.error(f"Error writing progressive results: {str(e)}")
            raise 