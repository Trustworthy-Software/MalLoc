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
    # Keep the full signature including return type and parameter types
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
        parsing_result = interaction.get("parsing_result", {})
        if parsing_result.get("is_malicious") and parsing_result.get("confidence", 0) >= confidence_threshold:
            # Check if the behavior is in the predicted behaviors
            behaviors = parsing_result.get("behaviors", [])
            # Convert behavior names to IDs using more flexible matching
            behavior_ids = []
            for b in behaviors:
                b = b.lower()  # Convert to lowercase for case-insensitive matching
                if "privacy" in b and "steal" in b:
                    behavior_ids.append("1")
                elif "sms" in b or "call" in b:
                    behavior_ids.append("2")
                elif "remote" in b and "control" in b:
                    behavior_ids.append("3")
                elif "bank" in b or "financial" in b:
                    behavior_ids.append("4")
                elif "ransom" in b:
                    behavior_ids.append("5")
                elif "accessibility" in b:
                    behavior_ids.append("6")
                elif "privilege" in b and "escalation" in b:
                    behavior_ids.append("7")
                elif "stealthy" in b and "download" in b:
                    behavior_ids.append("8")
                elif "aggressive" in b and "advertising" in b:
                    behavior_ids.append("9")
                elif "miner" in b:
                    behavior_ids.append("10")
                elif "tricky" in b and "behavior" in b:
                    behavior_ids.append("11")
                elif "premium" in b and "service" in b:
                    behavior_ids.append("12")
            
            if str(behavior_id) in behavior_ids:
                # Normalize the class name
                class_name = normalize_class_name(interaction["class_name"])
                pred_classes.add(class_name)
    return pred_classes

def extract_predicted_methods(llm_interaction_file, behavior_id):
    """
    Extract predicted methods from LLM interaction file.
    Returns a set of (class_name, signature) tuples.
    """
    predicted_methods = set()
    try:
        with open(llm_interaction_file, 'r') as f:
            data = json.load(f)
            for interaction in data.get('interactions', []):
                parsing_result = interaction.get('parsing_result', {})
                behaviors = parsing_result.get("behaviors", [])
                # Convert behavior names to IDs using more flexible matching
                behavior_ids = []
                for b in behaviors:
                    b = b.lower()  # Convert to lowercase for case-insensitive matching
                    if "privacy" in b and "steal" in b:
                        behavior_ids.append("1")
                    elif "sms" in b or "call" in b:
                        behavior_ids.append("2")
                    elif "remote" in b and "control" in b:
                        behavior_ids.append("3")
                    elif "bank" in b or "financial" in b:
                        behavior_ids.append("4")
                    elif "ransom" in b:
                        behavior_ids.append("5")
                    elif "accessibility" in b:
                        behavior_ids.append("6")
                    elif "privilege" in b and "escalation" in b:
                        behavior_ids.append("7")
                    elif "stealthy" in b and "download" in b:
                        behavior_ids.append("8")
                    elif "aggressive" in b and "advertising" in b:
                        behavior_ids.append("9")
                    elif "miner" in b:
                        behavior_ids.append("10")
                    elif "tricky" in b and "behavior" in b:
                        behavior_ids.append("11")
                    elif "premium" in b and "service" in b:
                        behavior_ids.append("12")
                
                if str(behavior_id) in behavior_ids:
                    class_name = normalize_class_name(interaction["class_name"])
                    for method in parsing_result.get("involved_methods", []):
                        method_signature = method.get("method_signature", "")
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
    pred_classes = {normalize_class_name(c) for c in pred_classes}
    
    # Calculate true positives, false positives, and false negatives
    true_positives = len(gt_classes & pred_classes)
    false_positives = len(pred_classes - gt_classes)
    false_negatives = len(gt_classes - pred_classes)
    
    # Calculate metrics
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # Calculate accuracy including true negatives
    true_negatives = total_classes - len(gt_classes) - false_positives
    accuracy = (true_positives + true_negatives) / total_classes
    
    return accuracy, precision, recall, f1, len(pred_classes)

def evaluate_method_level(gt_methods, pred_methods, total_methods):
    """
    Evaluate method-level performance with improved accuracy calculation.
    """
    if not gt_methods or total_methods <= 0:
        return 0.0, 0.0, 0.0, 0.0, 0
    
    # Normalize ground truth methods
    gt_methods = {(normalize_class_name(c), normalize_method_signature(s)) for c, _, s in gt_methods}
    
    # Calculate true positives, false positives, and false negatives
    true_positives = len(gt_methods & pred_methods)
    false_positives = len(pred_methods - gt_methods)
    false_negatives = len(gt_methods - pred_methods)
    
    # Calculate metrics
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # Calculate accuracy including true negatives
    true_negatives = total_methods - len(gt_methods) - false_positives
    accuracy = (true_positives + true_negatives) / total_methods
    
    return accuracy, precision, recall, f1, len(pred_methods)

def calculate_overall_metrics(summary):
    """Calculate overall metrics across all behaviors for each LLM."""
    llm_metrics = defaultdict(lambda: {
        'class_acc': [], 'class_prec': [], 'class_rec': [], 'class_f1': [],
        'method_acc': [], 'method_prec': [], 'method_rec': [], 'method_f1': [],
        'pred_classes': [], 'pred_methods': [],
        'true_positives': 0, 'false_positives': 0, 'false_negatives': 0,
        'total_gt_classes': 0, 'total_gt_methods': 0,
        'method_true_positives': 0, 'method_false_positives': 0, 'method_false_negatives': 0
    })
    
    # Collect metrics for each LLM
    for row in summary:
        llm = row['llm']
        # Track ground truth counts
        llm_metrics[llm]['total_gt_classes'] += row['num_classes']
        llm_metrics[llm]['total_gt_methods'] += row['num_methods']
        
        # Calculate class-level metrics
        true_positives = row['num_classes'] * row['class_prec']  # Classes correctly predicted
        false_positives = row['pred_classes'] - true_positives   # Classes incorrectly predicted
        false_negatives = row['num_classes'] - true_positives    # Classes missed
        
        llm_metrics[llm]['true_positives'] += true_positives
        llm_metrics[llm]['false_positives'] += false_positives
        llm_metrics[llm]['false_negatives'] += false_negatives
        
        # Calculate method-level metrics
        method_true_positives = row['num_methods'] * row['method_prec']  # Methods correctly predicted
        method_false_positives = row['pred_methods'] - method_true_positives  # Methods incorrectly predicted
        method_false_negatives = row['num_methods'] - method_true_positives  # Methods missed
        
        llm_metrics[llm]['method_true_positives'] += method_true_positives
        llm_metrics[llm]['method_false_positives'] += method_false_positives
        llm_metrics[llm]['method_false_negatives'] += method_false_negatives
        
        # Add to other metrics
        for metric in ['class_acc', 'class_prec', 'class_rec', 'class_f1',
                      'method_acc', 'method_prec', 'method_rec', 'method_f1',
                      'pred_classes', 'pred_methods']:
            llm_metrics[llm][metric].append(row[metric])
    
    # Calculate averages and overall metrics
    overall_results = []
    for llm, metrics in llm_metrics.items():
        # Calculate class-level overall metrics
        total_predictions = metrics['true_positives'] + metrics['false_positives']
        total_ground_truth = metrics['total_gt_classes']
        
        overall_precision = metrics['true_positives'] / total_predictions if total_predictions > 0 else 0
        overall_recall = metrics['true_positives'] / total_ground_truth if total_ground_truth > 0 else 0
        overall_f1 = 2 * (overall_precision * overall_recall) / (overall_precision + overall_recall) if (overall_precision + overall_recall) > 0 else 0
        
        # Calculate method-level overall metrics
        total_method_predictions = metrics['method_true_positives'] + metrics['method_false_positives']
        total_method_ground_truth = metrics['total_gt_methods']
        
        method_precision = metrics['method_true_positives'] / total_method_predictions if total_method_predictions > 0 else 0
        method_recall = metrics['method_true_positives'] / total_method_ground_truth if total_method_ground_truth > 0 else 0
        method_f1 = 2 * (method_precision * method_recall) / (method_precision + method_recall) if (method_precision + method_recall) > 0 else 0
        
        overall = {
            'llm': llm,
            'class_acc': sum(metrics['class_acc']) / len(metrics['class_acc']),
            'class_prec': overall_precision,
            'class_rec': overall_recall,
            'class_f1': overall_f1,
            'method_acc': sum(metrics['method_acc']) / len(metrics['method_acc']),
            'method_prec': method_precision,
            'method_rec': method_recall,
            'method_f1': method_f1,
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
    log_file = os.path.join(log_dir, f"baseline_evaluation_log_threshold_{confidence_threshold}.log")
    
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

def get_llm_result_files(results_dir, app_name):
    """Get LLM result files with error handling."""
    try:
        files = {}
        # Look for app-specific directory
        app_dir = None
        for d in os.listdir(results_dir):
            if app_name.lower() in d.lower():
                app_dir = os.path.join(results_dir, d)
                break
                
        if not app_dir:
            return files
            
        # Look for JSON files directly in the app directory
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
    results_dir = "0_Data/Results/MalLoc_Progressive/Malapp_baseline"
    confidence_threshold = 60  # Set threshold to 80 to match baseline output
    
    # Set up logging
    logger = setup_logging(results_dir, confidence_threshold)
    
    # Load total class and method counts from smali_stats.csv
    total_classes = 0
    total_methods = 0
    smali_stats_path = os.path.join("0_Data/Results/MalLoc_Progressive/Malapp", "evaluation_results", "smali_stats.csv")
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
                llm_files = get_llm_result_files(results_dir, app_name)
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
                        pred_methods = extract_predicted_methods(llm_file, behavior_id)
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
        csv_filename = os.path.join(eval_dir, f"baseline_llm_eval_summary_threshold_{confidence_threshold}.csv")
        with open(csv_filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=summary[0].keys())
            writer.writeheader()
            writer.writerows(summary)
        logger.info(f"\nSaved detailed summary to {csv_filename}")

        # Save overall results to CSV
        overall_filename = os.path.join(eval_dir, f"baseline_llm_eval_overall_threshold_{confidence_threshold}.csv")
        with open(overall_filename, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=overall_results[0].keys())
            writer.writeheader()
            writer.writerows(overall_results)
        logger.info(f"Saved overall results to {overall_filename}")
    except Exception as e:
        logger.error(f"Error saving results to CSV: {str(e)}")

if __name__ == "__main__":
    main() 