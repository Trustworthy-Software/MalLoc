import os
import json
from collections import defaultdict
from typing import Dict, List, Set, Any
import argparse

# Behavior ID to name mapping
BEHAVIOR_NAMES = {
    1: "Privacy Stealing",
    2: "SMS/CALL Abuse",
    3: "Remote Control",
    4: "Bank/Financial Stealing",
    5: "Ransom",
    6: "Accessibility Abuse",
    7: "Privilege Escalation",
    8: "Stealthy Download",
    9: "Aggressive Advertising",
    10: "Miner",
    11: "Tricky Behavior",
    12: "Premium Service Abuse"
}

def get_app_directories(results_dir: str) -> Dict[str, List[str]]:
    """Get all app directories from the results directory, organized by app hash."""
    app_dirs = defaultdict(list)
    for behavior_dir in os.listdir(results_dir):
        if behavior_dir.startswith("behavior_"):
            behavior_path = os.path.join(results_dir, behavior_dir)
            if os.path.isdir(behavior_path):
                for app_dir in os.listdir(behavior_path):
                    app_path = os.path.join(behavior_path, app_dir)
                    if os.path.isdir(app_path):
                        app_dirs[app_dir].append(app_path)
    return app_dirs

def get_llm_interaction_files(app_dir: str) -> Dict[str, str]:
    """Get all LLM interaction files for an app directory."""
    llm_files = {}
    for fname in os.listdir(app_dir):
        if fname.startswith("llm_interaction_") and fname.endswith(".json"):
            llm_name = fname[len("llm_interaction_"):-len(".json")]
            llm_files[llm_name] = os.path.join(app_dir, fname)
    return llm_files

def extract_behavior_id(app_dir: str) -> int:
    """Extract behavior ID from the app directory path."""
    behavior_dir = os.path.basename(os.path.dirname(app_dir))
    return int(behavior_dir.split("_")[1])

def consolidate_app_results(app_dirs: List[str], llm_filter: str = None, 
                          class_confidence_threshold: float = 0.0,
                          method_confidence_threshold: float = 0.0,
                          behavior_ids: Set[int] = None) -> Dict[str, Any]:
    """Consolidate all LLM interaction results for an app across all behavior folders."""
    # Initialize result structure
    result = {
        "app_hash": os.path.basename(app_dirs[0]),  # Get app hash from the directory name
        "statistics": {
            "total_classes": 0,
            "total_methods": 0,
            "unique_methods": 0
        },
        "classes": {}
    }
    
    # Process each behavior directory for this app
    for app_dir in app_dirs:
        behavior_id = extract_behavior_id(app_dir)
        # Skip if behavior_id is not in the specified set
        if behavior_ids is not None and behavior_id not in behavior_ids:
            continue
            
        llm_files = get_llm_interaction_files(app_dir)
        if llm_filter:
            llm_files = {k: v for k, v in llm_files.items() if k == llm_filter}
        
        # Process each LLM file
        for llm_name, llm_file in llm_files.items():
            # Read and process LLM file in chunks
            with open(llm_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            for interaction in data.get("interactions", []):
                if interaction.get("stage") == "class" and interaction.get("parsing_result", {}).get("is_malicious", False):
                    class_name = interaction["class_name"]
                    
                    # Skip if class confidence is below threshold
                    if interaction["parsing_result"].get("confidence", 0) < class_confidence_threshold:
                        continue
                    
                    # Initialize class if not exists
                    if class_name not in result["classes"]:
                        result["classes"][class_name] = {
                            "class_name": class_name,
                            "behaviors": []
                        }
                    
                    # Add behavior information
                    behavior_entry = {
                        "behavior_id": behavior_id,
                        "behavior_name": BEHAVIOR_NAMES.get(behavior_id, f"Unknown Behavior {behavior_id}"),
                        "confidence": interaction["parsing_result"].get("confidence", 0),
                        "explanation": interaction["parsing_result"].get("explanation", ""),
                        "Human Review": "Agree (default)",
                        "methods": []
                    }
                    
                    # Find corresponding methods interaction
                    methods_interaction = None
                    for m_interaction in data.get("interactions", []):
                        if (m_interaction.get("stage") == "methods" and 
                            m_interaction.get("class_name") == class_name):
                            methods_interaction = m_interaction
                            break
                    
                    # Add methods if found
                    if methods_interaction:
                        for method in methods_interaction.get("parsing_result", {}).get("involved_methods", []):
                            # Skip if method confidence is below threshold
                            if method.get("confidence", 0) < method_confidence_threshold:
                                continue
                                
                            method_info = {
                                "signature": method.get("method_signature", ""),
                                "confidence": method.get("confidence", 0),
                                "role": method.get("role", ""),
                                "Human Review": "Agree (default)"
                            }
                            behavior_entry["methods"].append(method_info)
                    
                    # Only add behavior if it has methods or meets confidence threshold
                    if behavior_entry["methods"] or behavior_entry["confidence"] >= class_confidence_threshold:
                        result["classes"][class_name]["behaviors"].append(behavior_entry)
    
    # Sort behaviors within each class by behavior_id
    for class_data in result["classes"].values():
        class_data["behaviors"].sort(key=lambda x: x["behavior_id"])
    
    # Calculate statistics
    total_methods = 0
    unique_methods = set()
    
    for class_data in result["classes"].values():
        for behavior in class_data["behaviors"]:
            for method in behavior["methods"]:
                total_methods += 1
                unique_methods.add(method["signature"])
    
    # Update statistics
    result["statistics"] = {
        "total_classes": len(result["classes"]),
        "total_methods": total_methods,
        "unique_methods": len(unique_methods)
    }
    
    return result

def validate_confidence(value: str) -> float:
    """Validate that confidence value is between 0 and 100."""
    try:
        confidence = float(value)
        if not 0 <= confidence <= 100:
            raise argparse.ArgumentTypeError(f"Confidence must be between 0 and 100, got {confidence}")
        return confidence
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid confidence value: {value}")

def validate_behavior_ids(value: str) -> Set[int]:
    """Validate and parse behavior IDs."""
    try:
        ids = set()
        for id_str in value.split(','):
            id_int = int(id_str.strip())
            if not 1 <= id_int <= 12:  # Valid behavior IDs are 1-12
                raise argparse.ArgumentTypeError(f"Behavior ID must be between 1 and 12, got {id_int}")
            ids.add(id_int)
        return ids
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid behavior ID format. Use comma-separated numbers (e.g., '1,2,3')")

def main():
    parser = argparse.ArgumentParser(description="Consolidate LLM detection results.")
    parser.add_argument("--llm", type=str, default=None, help="Specify a particular LLM to consolidate results for.")
    parser.add_argument("--class-confidence", type=validate_confidence, default=0.0,
                      help="Minimum confidence threshold for classes (0 to 100)")
    parser.add_argument("--method-confidence", type=validate_confidence, default=0.0,
                      help="Minimum confidence threshold for methods (0 to 100)")
    parser.add_argument("--behaviors", type=validate_behavior_ids, default=None,
                      help="Comma-separated list of behavior IDs to include (e.g., '1,2,3')")
    args = parser.parse_args()

    results_dir = "0_Data/Results/MalLoc_Progressive/RuMMs"
    output_dir = os.path.join(results_dir, "consolidated_results")
    os.makedirs(output_dir, exist_ok=True)
    
    # Get all app directories, organized by app hash
    app_dirs_dict = get_app_directories(results_dir)
    
    for app_hash, app_dirs in app_dirs_dict.items():
        print(f"Processing app {app_hash}...")
        try:
            consolidated = consolidate_app_results(
                app_dirs, 
                llm_filter=args.llm,
                class_confidence_threshold=args.class_confidence,
                method_confidence_threshold=args.method_confidence,
                behavior_ids=args.behaviors
            )
            llm_suffix = f"_{args.llm}" if args.llm else ""
            conf_suffix = f"_c{args.class_confidence:.0f}_m{args.method_confidence:.0f}" if args.class_confidence > 0 or args.method_confidence > 0 else ""
            behavior_suffix = f"_b{'-'.join(map(str, sorted(args.behaviors)))}" if args.behaviors else ""
            output_file = os.path.join(output_dir, f"{app_hash}{llm_suffix}{conf_suffix}{behavior_suffix}_consolidated.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(consolidated, f, indent=2, ensure_ascii=False)
            print(f"Saved consolidated results to {output_file}")
        except Exception as e:
            print(f"Error processing app {app_hash}: {str(e)}")

if __name__ == "__main__":
    main() 