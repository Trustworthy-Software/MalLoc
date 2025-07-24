import os
import logging
import time
import argparse
from typing import List, Dict, Any, Optional
from config import load_config, validate_config, load_apk_hashes, find_apk_path, create_output_dirs
from AppUtils import decompileAPK, buildCallGraph, cleanupFiles
from ProgressiveAnalysisUtils import analyze_app_progressive
from BaselineAnalysisUtils import analyze_app_baseline
from ExcelUtils import ExcelWriter
from logger import setup_logger

def main():
    parser = argparse.ArgumentParser(description="MalLoc Analysis")
    parser.add_argument('--config', type=str, default='config.json', help='Path to config file (default: config.json)')
    args = parser.parse_args()

    config = load_config(args.config)
    validate_config(config)

    # Configure logging using the setup_logger function
    logger = setup_logger(config.log_level)
    
    # Create output directories
    create_output_dirs(config)
    
    # Load APK hashes from file
    apk_hashes = load_apk_hashes(config.hash_file)
    if not apk_hashes:
        logger.error("No APK hashes found in hash file")
        return
    
    logger.info(f"Found {len(apk_hashes)} APK hashes to analyze")
    
    # Process each APK
    for i, apk_hash in enumerate(apk_hashes, 1):
        logger.info(f"Processing APK {i}/{len(apk_hashes)}: {apk_hash}")
        
        # Find APK file in subfolders
        apk_path = find_apk_path(config.input_path, apk_hash)
        if not apk_path:
            logger.warning(f"APK not found for hash: {apk_hash}")
            continue
        
        try:
            # Phase 1: Decompile APK
            phase1_start = time.time()
            print(f"⚡ START Phase 1: {time.strftime('%Y-%m-%d %H:%M:%S')} ⚡")
            print("--- ⭕ Decompiling with ApkTool.")
            decompile_success = decompileAPK(apk_path)
            if not decompile_success:
                logger.error(f"Failed to decompile APK: {apk_hash}")
                continue
            phase1_time = time.time() - phase1_start
            print("--- ✅ Success.")
            print(f"⚡ END   Phase 1: {time.strftime('%Y-%m-%d %H:%M:%S')} ⚡")
            print(f"⏱️ TIME  Phase 1: {phase1_time:.2f} seconds\n")
            
            # Phase 2: Build Call Graph if enabled
            phase2_start = time.time()
            print(f"⚡ START Phase 2: {time.strftime('%Y-%m-%d %H:%M:%S')} ⚡")
            if config.use_call_graph:
                buildCallGraph(apk_hash)
            phase2_time = time.time() - phase2_start
            print(f"⚡ END   Phase 2: {time.strftime('%Y-%m-%d %H:%M:%S')} ⚡")
            print(f"⏱️ TIME  Phase 2: {phase2_time:.2f} seconds\n")
            
            # Phase 3: Analysis based on selected approach
            phase3_start = time.time()
            print(f"⚡ START Phase 3: {time.strftime('%Y-%m-%d %H:%M:%S')} ⚡")
            excel_writer = ExcelWriter(config.output_dir)
            
            if config.analysis_approach == "progressive":
                # Progressive analysis for each selected behavior
                for behavior_id in config.selected_behaviors:
                    behavior_start = time.time()
                    # Check if Excel file already exists for this app and behavior
                    behavior_dir = os.path.join(config.output_dir, f"behavior_{behavior_id}")
                    app_dir = os.path.join(behavior_dir, apk_hash)
                    excel_file = os.path.join(app_dir, f"{apk_hash}_behavior_{behavior_id}_results.xlsx")
                    if os.path.exists(excel_file):
                        logger.info(f"Skipping APK {apk_hash} for behavior {behavior_id}: results already exist at {excel_file}")
                        continue
                    
                    # Perform progressive analysis
                    results, llm_metrics, total_classes = analyze_app_progressive(
                        apk_hash,
                        behavior_id,
                        config,
                        config.llm_configs
                    )
                    
                    # Write results to Excel
                    excel_writer.write_progressive_results(
                        apk_hash,
                        behavior_id,
                        results,
                        [llm.name for llm in config.llm_configs],
                        total_classes
                    )
                    
                    behavior_time = time.time() - behavior_start
                    logger.info(f"Completed behavior {behavior_id} analysis in {behavior_time:.2f} seconds")
            else:
                # Baseline analysis for each selected behavior
                for behavior_id in config.selected_behaviors:
                    baseline_start = time.time()
                    # Check if Excel file already exists for this app and behavior
                    behavior_dir = os.path.join(config.output_dir, f"behavior_{behavior_id}")
                    app_dir = os.path.join(behavior_dir, apk_hash)
                    excel_file = os.path.join(app_dir, f"{apk_hash}_behavior_{behavior_id}_baseline_results.xlsx")
                    if os.path.exists(excel_file):
                        logger.info(f"Skipping APK {apk_hash} for behavior {behavior_id}: baseline results already exist at {excel_file}")
                        continue
                    
                    # Perform baseline analysis
                    results, llm_metrics, total_classes = analyze_app_baseline(
                        apk_hash,
                        behavior_id,
                        config,
                        config.llm_configs
                    )
                    
                    # Write results to Excel
                    excel_writer.write_baseline_results(
                        apk_hash,
                        behavior_id,
                        results,
                        [llm.name for llm in config.llm_configs],
                        total_classes
                    )
                    
                    baseline_time = time.time() - baseline_start
                    logger.info(f"Completed baseline analysis for behavior {behavior_id} in {baseline_time:.2f} seconds")
            
            phase3_time = time.time() - phase3_start
            print(f"⚡ END   Phase 3: {time.strftime('%Y-%m-%d %H:%M:%S')} ⚡")
            print(f"⏱️ TIME  Phase 3: {phase3_time:.2f} seconds\n")
            
            # Phase 4: Cleanup
            phase4_start = time.time()
            print(f"⚡ START Cleaning: {time.strftime('%Y-%m-%d %H:%M:%S')} ⚡")
            print("--- 🗑️ Deleting Folders.")
            cleanupFiles(apk_hash)
            phase4_time = time.time() - phase4_start
            print(f"⚡ END   Cleaning: {time.strftime('%Y-%m-%d %H:%M:%S')} ⚡")
            print(f"⏱️ TIME  Cleaning: {phase4_time:.2f} seconds\n")
            
            # Log total processing time
            total_time = phase1_time + phase2_time + phase3_time + phase4_time
            logger.info(f"Total processing time for APK {apk_hash}: {total_time:.2f} seconds")
            
        except Exception as e:
            logger.error(f"Error processing APK {apk_hash}: {str(e)}")
            continue
    
    # Write summary statistics
    excel_writer.write_summary()
    logger.info("Analysis completed successfully")

if __name__ == "__main__":
    main() 