import os
import json
import re
import logging
from collections import defaultdict
from sklearn.metrics import precision_recall_fscore_support, accuracy_score

def normalize_class_name(class_name: str) -> str:
    """Normalize class name to handle different formats."""
    # Remove leading 'L' and trailing ';' if present
    if class_name.startswith('L'):
        class_name = class_name[1:]
    if class_name.endswith(';'):
        class_name = class_name[:-1]
    # Convert to simple class name (last part after last '/')
    return class_name.split('/')[-1]

def normalize_method_signature(signature: str) -> str:
    """Normalize method signature to handle different formats."""
    # Remove any line numbers
    signature = re.sub(r'\.line \d+', '', signature)
    # Remove any whitespace
    signature = signature.strip()
    return signature

def extract_predicted_classes(llm_interactions, behavior_id, gt_classes, confidence_threshold=0):
    """
    Returns set of class_names predicted as malicious for this behavior
    Args:
        llm_interactions: List of LLM interactions
        behavior_id: ID of the behavior
        gt_classes: Set of ground truth classes
        confidence_threshold: Minimum confidence score required for a prediction to be considered
    """
    pred_classes = set()
    for interaction in llm_interactions:
        if interaction["stage"] == "class":
            parsing_result = interaction["parsing_result"]
            if parsing_result.get("is_malicious") and parsing_result.get("confidence", 0) >= confidence_threshold:
                # Normalize the class name
                class_name = normalize_class_name(interaction["class_name"])
                pred_classes.add(class_name)
    return pred_classes

def extract_predicted_methods(llm_interaction_file):
    """
    Extract predicted methods from LLM interaction file.
    Returns a set of (class_name, signature) tuples.
    """
    predicted_methods = set()
    try:
        with open(llm_interaction_file, 'r') as f:
            data = json.load(f)
            for interaction in data.get('interactions', []):
                if interaction.get('stage') == 'methods':
                    parsing_result = interaction.get('parsing_result', {})
                    involved_methods = parsing_result.get('involved_methods', [])
                    class_name = normalize_class_name(interaction["class_name"])
                    for method in involved_methods:
                        method_signature = method.get('method_signature', '')
                        if method_signature:
                            # Normalize the method signature
                            method_signature = normalize_method_signature(method_signature)
                            predicted_methods.add((class_name, method_signature))
    except Exception as e:
        print(f"Error extracting predicted methods from {llm_interaction_file}: {e}")
    return predicted_methods

def evaluate_class_level(gt_classes, pred_classes, total_classes):
    """
    Evaluate class-level performance with improved accuracy calculation.
    """
    if not gt_classes or total_classes <= 0:
        return 0.0, 0.0, 0.0, 0.0, 0
    
    # Normalize ground truth class names
    gt_classes = {normalize_class_name(c) for c in gt_classes}
    y_true = [1 for _ in gt_classes]
    y_pred = [1 if c in pred_classes else 0 for c in gt_classes]
    
    # For negative classes (not in GT), add 0s
    for c in pred_classes:
        if c not in gt_classes:
            y_true.append(0)
            y_pred.append(1)
    
    # Add remaining negative classes
    remaining_negatives = total_classes - len(gt_classes) - len(pred_classes - gt_classes)
    if remaining_negatives > 0:
        y_true.extend([0] * remaining_negatives)
        y_pred.extend([0] * remaining_negatives)
    
    # Handle edge cases
    if not y_true or not y_pred:
        return 0.0, 0.0, 0.0, 0.0, len(pred_classes)
    
    acc = accuracy_score(y_true, y_pred)
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
    return acc, p, r, f1, len(pred_classes)

def print_method_matches_for_debug(gt_methods, pred_methods, behavior_id, llm_name):
    """Print debug information about method matches."""
    print(f"\n--- DEBUG: Method Matches for behavior_id={behavior_id}, LLM={llm_name} ---")
    print("Ground Truth Methods:")
    for c, sig in sorted(gt_methods):
        print(f"  {c} -> {sig}")
    print("\nPredicted Methods:")
    for c, sig in sorted(pred_methods):
        print(f"  {c} -> {sig}")
    print("\nMatches:")
    matches = gt_methods & pred_methods
    for c, sig in sorted(matches):
        print(f"  ✓ {c} -> {sig}")
    print("\nMissed (in GT but not predicted):")
    missed = gt_methods - pred_methods
    for c, sig in sorted(missed):
        print(f"  ✗ {c} -> {sig}")
    print("\nFalse Positives (predicted but not in GT):")
    false_pos = pred_methods - gt_methods
    for c, sig in sorted(false_pos):
        print(f"  ✗ {c} -> {sig}")
    print("--- END DEBUG ---\n")

def evaluate_method_level(gt_methods, pred_methods, total_methods):
    """
    Evaluate method-level performance with improved accuracy calculation.
    """
    if not gt_methods or total_methods <= 0:
        return 0.0, 0.0, 0.0, 0.0, 0
    
    # Normalize ground truth methods
    gt_methods = {(normalize_class_name(c), normalize_method_signature(s)) for c, _, s in gt_methods}
    
    all_methods = gt_methods | pred_methods
    y_true = [1 if m in gt_methods else 0 for m in all_methods]
    y_pred = [1 if m in pred_methods else 0 for m in all_methods]
    
    # Add remaining negative methods
    remaining_negatives = total_methods - len(gt_methods) - len(pred_methods - gt_methods)
    if remaining_negatives > 0:
        y_true.extend([0] * remaining_negatives)
        y_pred.extend([0] * remaining_negatives)
    
    # Handle edge cases
    if not y_true or not y_pred:
        return 0.0, 0.0, 0.0, 0.0, len(pred_methods)
    
    acc = accuracy_score(y_true, y_pred)
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
    return acc, p, r, f1, len(pred_methods)

def calculate_overall_metrics(summary):
    """Calculate overall metrics across all behaviors for each LLM."""
    llm_metrics = defaultdict(lambda: {
        'class_acc': [], 'class_prec': [], 'class_rec': [], 'class_f1': [],
        'method_acc': [], 'method_prec': [], 'method_rec': [], 'method_f1': [],
        'pred_classes': [], 'pred_methods': []
    })
    
    # Collect metrics for each LLM
    for row in summary:
        llm = row['llm']
        for metric in ['class_acc', 'class_prec', 'class_rec', 'class_f1',
                      'method_acc', 'method_prec', 'method_rec', 'method_f1',
                      'pred_classes', 'pred_methods']:
            llm_metrics[llm][metric].append(row[metric])
    
    # Calculate averages
    overall_results = []
    for llm, metrics in llm_metrics.items():
        overall = {
            'llm': llm,
            'class_acc': sum(metrics['class_acc']) / len(metrics['class_acc']),
            'class_prec': sum(metrics['class_prec']) / len(metrics['class_prec']),
            'class_rec': sum(metrics['class_rec']) / len(metrics['class_rec']),
            'class_f1': sum(metrics['class_f1']) / len(metrics['class_f1']),
            'method_acc': sum(metrics['method_acc']) / len(metrics['method_acc']),
            'method_prec': sum(metrics['method_prec']) / len(metrics['method_prec']),
            'method_rec': sum(metrics['method_rec']) / len(metrics['method_rec']),
            'method_f1': sum(metrics['method_f1']) / len(metrics['method_f1']),
            'avg_pred_classes': sum(metrics['pred_classes']) / len(metrics['pred_classes']),
            'avg_pred_methods': sum(metrics['pred_methods']) / len(metrics['pred_methods']),
            'total_pred_classes': sum(metrics['pred_classes']),
            'total_pred_methods': sum(metrics['pred_methods'])
        }
        overall_results.append(overall)
    
    return overall_results

def setup_logging(results_dir, confidence_threshold):
    """Set up logging configuration."""
    log_dir = os.path.join(results_dir, "evaluation_results")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"evaluation_log_threshold_{confidence_threshold}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def load_groundtruth(gt_path):
    """Load and validate ground truth data."""
    try:
        with open(gt_path, 'r', encoding='utf-8') as f:
            gt_data = json.load(f)
        
        # Validate ground truth structure
        if isinstance(gt_data, dict) and "groundtruth" in gt_data:
            return [gt_data]
        elif isinstance(gt_data, list):
            for item in gt_data:
                if not isinstance(item, dict) or "groundtruth" not in item:
                    raise ValueError("Invalid ground truth format: missing 'groundtruth' field")
            return gt_data
        else:
            raise ValueError("Invalid ground truth format: must be a list or dict with 'groundtruth' field")
    except json.JSONDecodeError:
        raise ValueError(f"Invalid JSON in ground truth file: {gt_path}")
    except Exception as e:
        raise ValueError(f"Error loading ground truth: {str(e)}")

def get_llm_result_files(results_dir, behavior_id, app_name):
    """Get LLM result files with error handling."""
    try:
        files = {}
        behavior_dir = os.path.join(results_dir, f"behavior_{behavior_id}")
        if not os.path.exists(behavior_dir):
            return files
            
        # Look for app-specific directory
        app_dir = None
        for d in os.listdir(behavior_dir):
            if app_name.lower() in d.lower():
                app_dir = os.path.join(behavior_dir, d)
                break
                
        if not app_dir:
            return files
            
        for fname in os.listdir(app_dir):
            if fname.startswith("llm_interaction_") and fname.endswith(".json"):
                llm_name = fname[len("llm_interaction_"):-len(".json")]
                files[llm_name] = os.path.join(app_dir, fname)
        return files
    except Exception as e:
        logging.error(f"Error getting LLM result files: {str(e)}")
        return {}

def main():
    gt_path = "0_Data/MalApp/MalApp_MalLoc_1_9_11_groundtruth.json"
    results_dir = "0_Data/Results/MalLoc_Progressive/Malapp"
    confidence_threshold = 85  # Set your desired confidence threshold here (0-100)
    
    # Set up logging
    logger = setup_logging(results_dir, confidence_threshold)
    
    # Load total class and method counts from smali_stats.csv
    total_classes = 0
    total_methods = 0
    smali_stats_path = os.path.join(results_dir, "evaluation_results", "smali_stats.csv")
    try:
        if os.path.exists(smali_stats_path):
            import csv
            with open(smali_stats_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    total_classes += 1
                    total_methods += int(row['Number of Methods'])
        else:
            logger.warning(f"smali_stats.csv not found at {smali_stats_path}. Using default values.")
            total_classes = 51  # Default value
            total_methods = 165  # Default value
    except Exception as e:
        logger.error(f"Error reading smali_stats.csv: {str(e)}")
        total_classes = 51  # Default value
        total_methods = 165  # Default value
    
    # Load ground truth
    try:
        gt_data = load_groundtruth(gt_path)
    except ValueError as e:
        logger.error(f"Error loading ground truth: {str(e)}")
        return
    
    if not gt_data:
        logger.error("No ground truth data found.")
        return
        
    summary = []
    total_classes_evaluated = 0
    total_methods_evaluated = 0
    evaluated_classes = set()  # Track unique classes evaluated
    evaluated_methods = set()  # Track unique methods evaluated
    
    # Process each app in ground truth
    for app_data in gt_data:
        app_name = app_data["app_name"]
        logger.info(f"\nProcessing app: {app_name}")
        
        # Process each behavior in the app
        for behavior in app_data["groundtruth"]:
            try:
                behavior_id = behavior["behavior_id"]
                behavior_name = behavior["behavior_name"]
                class_name = behavior["class_name"]
                
                # Get ground truth classes and methods
                gt_classes = set([class_name])
                gt_methods_by_class = defaultdict(set)
                gt_methods = set()
                
                # Handle both methods and method_groups
                if "methods" in behavior:
                    for m in behavior["methods"]:
                        line = m.get("line", 0)
                        signature = m["signature"]
                        gt_methods_by_class[class_name].add((line, signature))
                        gt_methods.add((class_name, line, signature))
                elif "method_groups" in behavior:
                    for group in behavior["method_groups"]:
                        for m in group:
                            line = m.get("line", 0)
                            signature = m["signature"]
                            gt_methods_by_class[class_name].add((line, signature))
                            gt_methods.add((class_name, line, signature))
                
                # Update evaluated counts
                evaluated_classes.update(gt_classes)
                evaluated_methods.update(gt_methods)
                
                # Get LLM result files
                llm_files = get_llm_result_files(results_dir, behavior_id, app_name)
                if not llm_files:
                    logger.warning(f"No LLM result files found for app {app_name}")
                    continue
                    
                for llm_name, llm_file in llm_files.items():
                    try:
                        with open(llm_file, 'r', encoding='utf-8') as f:
                            llm_data = json.load(f)
                        interactions = llm_data["interactions"]
                        
                        # Class-level
                        pred_classes = extract_predicted_classes(interactions, behavior_id, gt_classes, confidence_threshold)
                        acc_c, p_c, r_c, f1_c, num_pred_classes = evaluate_class_level(gt_classes, pred_classes, total_classes)
                        
                        # Method-level
                        pred_methods = extract_predicted_methods(llm_file)
                        acc_m, p_m, r_m, f1_m, num_pred_methods = evaluate_method_level(gt_methods, pred_methods, total_methods)
                        
                        logger.info(f"Behavior {behavior_id} ({behavior_name}) - LLM: {llm_name}")
                        logger.info(f"Classes evaluated: {len(gt_classes)}, Methods evaluated: {len(gt_methods)}")
                        logger.info(f"Classes predicted: {num_pred_classes}, Methods predicted: {num_pred_methods}")
                        
                        summary.append({
                            "app": app_name,
                            "behavior_id": behavior_id,
                            "behavior_name": behavior_name,
                            "llm": llm_name,
                            "confidence_threshold": confidence_threshold,
                            "num_classes": len(gt_classes),
                            "num_methods": len(gt_methods),
                            "total_classes": total_classes,
                            "total_methods": total_methods,
                            "pred_classes": num_pred_classes,
                            "pred_methods": num_pred_methods,
                            "class_acc": acc_c, "class_prec": p_c, "class_rec": r_c, "class_f1": f1_c,
                            "method_acc": acc_m, "method_prec": p_m, "method_rec": r_m, "method_f1": f1_m
                        })
                    except Exception as e:
                        logger.error(f"Error processing LLM file {llm_file}: {str(e)}")
                        continue
            except KeyError as e:
                logger.error(f"Missing required field in behavior data: {str(e)}")
                continue
            except Exception as e:
                logger.error(f"Error processing behavior: {str(e)}")
                continue

    # Update total evaluated counts
    total_classes_evaluated = len(evaluated_classes)
    total_methods_evaluated = len(evaluated_methods)

    if not summary:
        logger.error("No results found. Please check if the LLM interaction files exist in the app-specific subdirectories.")
        return

    # Print per-behavior results
    logger.info(f"\n=== Per-Behavior Results (Confidence Threshold: {confidence_threshold}) ===")
    logger.info(f"{'App':20} {'Behavior':20} {'LLM':10} | {'C-Acc':6} {'C-Prec':6} {'C-Rec':6} {'C-F1':6} | {'M-Acc':6} {'M-Prec':6} {'M-Rec':6} {'M-F1':6} | {'Pred-C':6} {'Pred-M':6}")
    for row in summary:
        logger.info(f"{row['app']:20} {row['behavior_name']:20} {row['llm']:10} | "
              f"{row['class_acc']:.2f}   {row['class_prec']:.2f}   {row['class_rec']:.2f}   {row['class_f1']:.2f} | "
              f"{row['method_acc']:.2f}   {row['method_prec']:.2f}   {row['method_rec']:.2f}   {row['method_f1']:.2f} | "
              f"{row['pred_classes']:6d} {row['pred_methods']:6d}")

    # Calculate and print overall results
    overall_results = calculate_overall_metrics(summary)
    logger.info(f"\n=== Overall Results Across All Behaviors (Confidence Threshold: {confidence_threshold}) ===")
    logger.info(f"Total classes in app: {total_classes}")
    logger.info(f"Total methods in app: {total_methods}")
    logger.info(f"Total unique classes evaluated: {total_classes_evaluated}")
    logger.info(f"Total unique methods evaluated: {total_methods_evaluated}")
    logger.info(f"Coverage: {total_classes_evaluated/total_classes*100:.1f}% classes, {total_methods_evaluated/total_methods*100:.1f}% methods")
    logger.info(f"{'LLM':10} | {'C-Acc':6} {'C-Prec':6} {'C-Rec':6} {'C-F1':6} | {'M-Acc':6} {'M-Prec':6} {'M-Rec':6} {'M-F1':6} | {'Avg-C':6} {'Avg-M':6} | {'Tot-C':6} {'Tot-M':6}")
    for row in overall_results:
        logger.info(f"{row['llm']:10} | "
              f"{row['class_acc']:.2f}   {row['class_prec']:.2f}   {row['class_rec']:.2f}   {row['class_f1']:.2f} | "
              f"{row['method_acc']:.2f}   {row['method_prec']:.2f}   {row['method_rec']:.2f}   {row['method_f1']:.2f} | "
              f"{row['avg_pred_classes']:6.1f} {row['avg_pred_methods']:6.1f} | "
              f"{row['total_pred_classes']:6d} {row['total_pred_methods']:6d}")

    # Create evaluation results directory
    eval_dir = os.path.join(results_dir, "evaluation_results")
    os.makedirs(eval_dir, exist_ok=True)

    # Save detailed summary to CSV
    try:
        import csv
        csv_filename = os.path.join(eval_dir, f"llm_eval_summary_threshold_{confidence_threshold}.csv")
        with open(csv_filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=summary[0].keys())
            writer.writeheader()
            writer.writerows(summary)
        logger.info(f"\nSaved detailed summary to {csv_filename}")

        # Save overall results to CSV
        overall_filename = os.path.join(eval_dir, f"llm_eval_overall_threshold_{confidence_threshold}.csv")
        with open(overall_filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=overall_results[0].keys())
            writer.writeheader()
            writer.writerows(overall_results)
        logger.info(f"Saved overall results to {overall_filename}")
    except Exception as e:
        logger.error(f"Error saving results to CSV: {str(e)}")

if __name__ == "__main__":
    main() 