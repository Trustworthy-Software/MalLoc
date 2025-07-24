# MalLoc: Towards Fine-grained Android Malicious Payload Localization via LLMs

This repository contains the replication package for MalLoc, a framework that uses Large Language Models (LLMs) to detect and localize malicious behaviors in Android applications through progressive analysis.

## Project Structure

```
.
├── 0_Data/                  # Data directory
│   ├── APKs/               # Sample APK files and ground truth
│   └── Results/            # Analysis results
└── 1_Code/                 # Source code
    ├── main.py             # Main entry point
    ├── config.py           # Configuration management
    ├── config.json         # Default configuration
    ├── config.MalApp.json  # Configuration for sample app
    └── [Other utilities]   # Supporting modules
```

## Prerequisites

- Python 3.8 or higher
- Java Development Kit (JDK) 8 or higher
- Android SDK tools (for APK analysis)
- Ollama (for local LLM support)
- OpenAI API key (for GPT models)

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd MalLocICSME
```

2. Install required Python packages.

3. Set up environment variables:
```bash
# Create .env file
echo "OPENAI_API_KEY=your_api_key_here" > .env
```

## Configuration

The framework can be configured through JSON configuration files:

1. `config.json`: Default configuration
2. `config.MalApp.json`: Configuration for the sample malicious app

Key configuration parameters:
- `selected_behaviors`: List of behaviors to analyze (1-12)
- `llm_configs`: LLM configurations (Ollama and/or OpenAI)
- `analysis_approach`: "progressive" or "baseline"
- `input_path`: Directory containing APK files
- `output_dir`: Directory for analysis results

## Usage

1. Place APK files in the configured input directory
2. Create a list of APK hashes to analyze
3. Run the analysis:
```bash
python 1_Code/main.py --config config.json
```

## Analysis Approaches

### Progressive Analysis
A two-phase analysis approach:
1. Class-level analysis to identify potentially malicious classes
2. Method-level analysis of identified classes

### Baseline Analysis
A simpler one-phase analysis approach that analyzes a class at once.

## Output

The analysis generates:
- Excel reports with detailed findings
- JSON logs of LLM interactions
- Summary statistics
- Per-behavior analysis results

