import os
import re
import logging
import json
import datetime
from typing import List, Dict, Any, Tuple, Set
from config import AnalysisConfig, LLMConfig, get_behavior_description
from AppUtils import getSmaliFiles, getDecompiledPath
from LLMUtils import create_llm_interface

logger = logging.getLogger(__name__)

def accumulate_llm_interaction(accumulator, apk_hash, behavior_id, class_name, llm_name, prompt, llm_output, parsing_result=None):
    accumulator.append({
        'timestamp': datetime.datetime.now().isoformat(),
        'apk_hash': apk_hash,
        'behavior_id': behavior_id,
        'class_name': class_name,
        'llm_name': llm_name,
        'prompt': prompt,
        'llm_output': llm_output,
        'parsing_result': parsing_result
    })

def save_llm_interactions_json(app_dir, apk_hash, behavior_id, llm_name, interactions):
    # Filter interactions to keep only positive predictions
    filtered_interactions = []
    for interaction in interactions:
        if interaction.get('parsing_result', {}).get('is_malicious', False):
            filtered_interactions.append(interaction)
    
    # Only save if there are positive predictions
    if filtered_interactions:
        filename = os.path.join(app_dir, f'llm_interaction_{llm_name}.json')
        data = {
            'apk_hash': apk_hash,
            'behavior_id': behavior_id,
            'llm_name': llm_name,
            'interactions': filtered_interactions
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

def parse_baseline_output(text: str) -> Dict[str, Any]:
    """
    Parse baseline output format for class analysis.
    """
    result = {
        "is_malicious": False,
        "confidence": 0,
        "explanation": "",
        "behaviors": [],
        "involved_methods": []
    }
    
    current_section = None
    current_method = None
    
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
            
        if line.startswith("IS_MALICIOUS:"):
            value = line[len("IS_MALICIOUS:"):].strip().lower()
            result["is_malicious"] = value in ("yes", "true", "1")
        elif line.startswith("CONFIDENCE:"):
            try:
                result["confidence"] = int(line[len("CONFIDENCE:"):].strip())
            except ValueError:
                result["confidence"] = 0
        elif line.startswith("EXPLANATION:"):
            result["explanation"] = line[len("EXPLANATION:"):].strip()
        elif line.startswith("BEHAVIOR:"):
            behaviors = line[len("BEHAVIOR:"):].strip()
            result["behaviors"] = [b.strip() for b in behaviors.split(",")]
        elif line.startswith("METHOD:"):
            if current_method:
                result["involved_methods"].append(current_method)
            current_method = {
                "method_signature": line[len("METHOD:"):].strip(),
                "role": "",
                "confidence": result["confidence"]  # Use class confidence as default
            }
        elif line.startswith("ROLE:"):
            if current_method:
                current_method["role"] = line[len("ROLE:"):].strip()
    
    # Add the last method if exists
    if current_method:
        result["involved_methods"].append(current_method)
    
    return result

def analyze_class_with_llm(
    class_content: str,
    llm_interface: Any,
    metrics: Dict[str, int],
    app_dir: str,
    apk_hash: str,
    behavior_id: int,
    class_name: str,
    llm_interactions_acc: list
) -> Dict[str, Any]:
    """
    Analyze a class for all possible malicious behaviors at once
    Args:
        class_content: Content of the Smali class
        llm_interface: LLM interface to use
        metrics: Dictionary to track LLM metrics
    Returns:
        Dictionary containing analysis results
    """
    prompt = f"""
You are an expert in Android malware analysis. Analyze the following Smali class and determine if it implements any malicious behaviors.

Smali Class:
{class_content}

Possible Malicious Behaviors:
1. Privacy Stealing
2. SMS/CALL Abuse
3. Remote Control
4. Bank/Financial Stealing
5. Ransom
6. Accessibility Abuse
7. Privilege Escalation
8. Stealthy Download
9. Aggressive Advertising
10. Miner
11. Tricky Behavior
12. Premium Service Abuse

IMPORTANT: For your answer, use the following format:
IS_MALICIOUS: <yes or no>
CONFIDENCE: <confidence score 0-100>
EXPLANATION: <detailed explanation of why this class is or isn't malicious>

BEHAVIOR: <one or several behaviors from the list above, separated by comma>

Involved methods:
METHOD: <the first line of the method exactly as it appears in the Smali code>
ROLE: <role description>
METHOD: <next method>
ROLE: <role description>
...

Do not include any other text, markdown, or formatting.
"""

    try:
        result = llm_interface.analyze(prompt)
        metrics["total_tokens"] += result.get("total_tokens", 0)
        metrics["total_requests"] += 1
        parsed = parse_baseline_output(result["content"])
        accumulate_llm_interaction(
            llm_interactions_acc, apk_hash, behavior_id, class_name, llm_interface.name, prompt, result["content"], parsed
        )
        return {
            "is_malicious": parsed["is_malicious"],
            "confidence": parsed["confidence"],
            "explanation": parsed["explanation"],
            "behaviors": parsed["behaviors"],
            "involved_methods": parsed["involved_methods"],
            "raw_response": result["content"]
        }
    except Exception as e:
        logger.error(f"Error in class analysis: {str(e)}")
        return {
            "is_malicious": False,
            "confidence": 0,
            "explanation": f"Error: {str(e)}",
            "behaviors": [],
            "involved_methods": [],
            "raw_response": ""
        }

def analyze_app_baseline(
    apk_hash: str,
    behavior_id: int,
    config: AnalysisConfig,
    llm_configs: List[LLMConfig]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], int]:
    """
    Baseline analysis of an app for all malicious behaviors at once
    Args:
        apk_hash: Hash of the APK file
        behavior_id: ID of the behavior (kept for compatibility)
        config: Analysis configuration
        llm_configs: List of LLM configurations
    Returns:
        Tuple containing:
        - List of results (malicious classes found)
        - Dictionary of LLM metrics
        - Total number of classes analyzed
    """
    try:
        # Keep the behavior-specific directory structure for compatibility
        behavior_dir = os.path.join(config.output_dir, f"behavior_{behavior_id}")
        app_dir = os.path.join(behavior_dir, apk_hash)
        os.makedirs(app_dir, exist_ok=True)
        log_file = os.path.join(app_dir, f"baseline_analysis_log.txt")
        logger = logging.getLogger('MalLoc')
        file_handler = logging.FileHandler(log_file, mode='w')
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)
        
        # Initialize results and metrics
        results = []
        llm_metrics = {llm.name: {"total_tokens": 0, "total_requests": 0, "malicious_classes": 0} for llm in llm_configs}
        total_classes = 0
        llm_interfaces = [create_llm_interface(llm_config) for llm_config in llm_configs]
        
        # Initialize interaction accumulators for each LLM
        llm_interactions = {llm.name: [] for llm in llm_configs}
        
        # Get Smali files
        if config.smali_subdir:
            decompiled_path = getDecompiledPath(apk_hash)
            smali_files = []
            # Handle both string and list of strings for smali_subdir
            subdirs = [config.smali_subdir] if isinstance(config.smali_subdir, str) else config.smali_subdir
            for subdir in subdirs:
                target_dir = os.path.join(decompiled_path, subdir)
                if os.path.exists(target_dir):
                    logger.info(f"Searching for Smali files in: {target_dir}")
                    for root, _, files in os.walk(target_dir):
                        for file in files:
                            if file.endswith('.smali'):
                                smali_files.append(os.path.join(root, file))
                else:
                    logger.warning(f"Subdirectory not found: {target_dir}")
        else:
            smali_files = getSmaliFiles(apk_hash)
        
        total_classes = len(smali_files)
        logger.info(f"Found {total_classes} Smali files to analyze")
        
        # Process classes in batches to manage memory
        batch_size = 100
        for batch_start in range(0, total_classes, batch_size):
            batch_end = min(batch_start + batch_size, total_classes)
            batch_files = smali_files[batch_start:batch_end]
            
            # Process each class in the batch
            for class_idx, smali_file in enumerate(batch_files, batch_start + 1):
                class_name = get_class_name(smali_file)
                logger.info(f"Processing class {class_idx}/{total_classes}: {class_name}")
                
                # Read class content
                with open(smali_file, 'r', encoding='utf-8') as f:
                    class_content = f.read()
                
                malicious_llms = []
                class_results = {
                    "className": class_name,
                    "classContent": class_content,
                    "llm_results": {}
                }
                
                # Analyze with each LLM
                for llm, interface in zip(llm_configs, llm_interfaces):
                    try:
                        result = analyze_class_with_llm(
                            class_content,
                            interface,
                            llm_metrics[llm.name],
                            app_dir,
                            apk_hash,
                            behavior_id,
                            class_name,
                            llm_interactions[llm.name]  # Pass the accumulator for this LLM
                        )
                        class_results["llm_results"][llm.name] = result
                        
                        if result.get("is_malicious", False):
                            malicious_llms.append(llm.name)
                            llm_metrics[llm.name]["malicious_classes"] += 1
                    except Exception as e:
                        logger.error(f"Error analyzing class {class_name} with LLM {llm.name}: {str(e)}")
                        continue
                
                if malicious_llms:
                    llm_str = ", ".join(malicious_llms)
                    logger.info(f"Found malicious class {class_name} (Detected by: {llm_str})")
                    results.append(class_results)
                
                # Clear class content from memory
                del class_content
                del class_results
                
                if class_idx % 10 == 0 or class_idx == total_classes:
                    percentage = (class_idx / total_classes) * 100
                    logger.info(f"Progress: {class_idx} classes out of {total_classes} [{percentage:.2f}%]")
            
            # Force garbage collection after each batch
            import gc
            gc.collect()
        
        # Save accumulated interactions for each LLM
        for llm in llm_configs:
            if llm_interactions[llm.name]:
                save_llm_interactions_json(
                    app_dir,
                    apk_hash,
                    behavior_id,
                    llm.name,
                    llm_interactions[llm.name]
                )
        
        # Generate summary
        summary_lines = []
        summary_lines.append("\n--- 📊 BASELINE ANALYSIS SUMMARY")
        summary_lines.append(f"--- 📊 Total Classes Analyzed: {total_classes}")
        summary_lines.append(f"--- 📊 Total Malicious Classes Found: {len(results)}")
        
        summary_lines.append("\n--- 📊 Per-LLM Statistics:")
        for llm_name, metrics in llm_metrics.items():
            detection_rate = (metrics["malicious_classes"]/total_classes*100) if total_classes > 0 else 0
            summary_lines.append(f"      - {llm_name}:")
            summary_lines.append(f"        • Malicious Classes: {metrics['malicious_classes']} ({detection_rate:.2f}%)")
            summary_lines.append(f"        • Total Tokens: {metrics['total_tokens']}")
            summary_lines.append(f"        • Total Requests: {metrics['total_requests']}")
        
        # Print and log summary
        summary_text = "\n".join(summary_lines)
        print(summary_text)
        logger.info(summary_text)
        
        # Save summary to file
        summary_file = os.path.join(app_dir, "baseline_analysis_summary.txt")
        with open(summary_file, 'w') as f:
            f.write(summary_text)
        
        # Cleanup
        logger.removeHandler(file_handler)
        file_handler.close()
        
        return results, llm_metrics, total_classes
        
    except Exception as e:
        error_msg = f"Error in baseline analysis of app {apk_hash}: {str(e)}"
        logger.error(error_msg)
        if 'file_handler' in locals() and file_handler in logger.handlers:
            logger.removeHandler(file_handler)
            file_handler.close()
        return [], {}, 0

def get_class_name(smali_file: str) -> str:
    """Extract class name from Smali file path"""
    return os.path.splitext(os.path.basename(smali_file))[0] 