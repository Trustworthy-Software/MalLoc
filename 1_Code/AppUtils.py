from typing import List, Dict, Optional, Tuple
import subprocess
import datetime
import requests
import shutil
import time
import json
import os
import re
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# App Class
class App:

	# Fields
	sha256: Optional[str] = None
	pkgName: Optional[str] = None
	apkPath: str
	alreadyDownloaded: bool = False
	name: str  # For local APKs, this will be the filename without extension

	# To store the code
	smaliCodeFiles: Optional[List[str]] = None
	smaliCodeClasses: Optional[List[Dict]] = None
	smaliCodeMethods: Optional[List[Dict]] = None

	# To store the call graph
	callGraphNodes: Optional[List[str]] = None

	# To keep track of the number of classes and methods
	numNodes: int = -1
	numClasses: int = -1
	numMethods: int = -1

	# Initialize the App object.
	# Parameters:
	# - apk_path (str): Path to the APK file
	# - tmp_path (str): Temporary path to store decompiled files
	def __init__(self, apk_path: str, tmp_path: str):
		self.apkPath = apk_path
		self.name = Path(apk_path).stem
		
		# If it's a local APK, we don't need to download
		self.alreadyDownloaded = True

	# Print to a string
	def __str__(self) -> str:
		avgNumMethodsPerClass = self.numMethods / self.numClasses if self.numClasses > 0 else 0
		return (
			"\n⭐ --- App Summary --- ⭐\n"
			"--- 🔢 N. Classes               : {}\n"
			"--- 🔢 N. Methods               : {}\n"
			"--- 🔢 Avg N. methods per class : {}\n"
		).format(self.numClasses, self.numMethods, int(avgNumMethodsPerClass))
 
	### Apk Related ###
	def process(self, use_call_graph: bool = True):
		"""Process the APK file through all analysis phases."""
		try:
			# Phase 1: Decompile
			startTime = datetime.datetime.now()
			self.decompileWithApktool()
			endTime = datetime.datetime.now()
			elapsedTime = endTime - startTime
			print("⚡ END   Phase 1: {} ⚡".format(endTime.strftime("%Y-%m-%d %H:%M:%S")))
			print("⏱️ TIME  Phase 1: {} seconds\n".format(int(elapsedTime.total_seconds())))

			# Phase 2: Smali Code Extraction
			startTime = datetime.datetime.now()
			print("⚡ START Phase 2: {} ⚡".format(startTime.strftime("%Y-%m-%d %H:%M:%S")))
			self.getSmaliCodeFiles()
			endTime = datetime.datetime.now()
			elapsedTime = endTime - startTime
			print("⚡ END   Phase 2: {} ⚡".format(endTime.strftime("%Y-%m-%d %H:%M:%S")))
			print("⏱️ TIME  Phase 2: {} seconds\n".format(int(elapsedTime.total_seconds())))
			
			# Phase 3: Call Graph (if enabled)
			if use_call_graph:
				startTime = datetime.datetime.now()
				print("⚡ START Phase 3: {} ⚡".format(startTime.strftime("%Y-%m-%d %H:%M:%S")))
				self.buildCG()
				self.getNodesFromCG()
				endTime = datetime.datetime.now()
				elapsedTime = endTime - startTime
				print("⚡ END   Phase 3: {} ⚡".format(endTime.strftime("%Y-%m-%d %H:%M:%S")))
				print("⏱️ TIME  Phase 3: {} seconds\n".format(int(elapsedTime.total_seconds())))

			# Phase 4: Method Extraction
			startTime = datetime.datetime.now()
			print("⚡ START Phase 4: {} ⚡".format(startTime.strftime("%Y-%m-%d %H:%M:%S")))
			self.getSmaliClasses()
			if use_call_graph:
				self.filterSmaliClassesWithCGNodes()
			endTime = datetime.datetime.now()
			elapsedTime = endTime - startTime
			print("⚡ END   Phase 4: {} ⚡".format(endTime.strftime("%Y-%m-%d %H:%M:%S")))
			print("⏱️ TIME  Phase 4: {} seconds\n".format(int(elapsedTime.total_seconds())))

		except Exception as e:
			print("--- ⚠️ [STOP PROCESSING APP]: {}\n".format(e))
			raise
		finally:
			# Phase 5: Cleanup
			startTime = datetime.datetime.now()
			print("⚡ START Cleaning: {} ⚡".format(startTime.strftime("%Y-%m-%d %H:%M:%S")))
			self.deleteAll()
			endTime = datetime.datetime.now()
			elapsedTime = endTime - startTime
			print("⚡ END   Cleaning: {} ⚡".format(endTime.strftime("%Y-%m-%d %H:%M:%S")))
			print("⏱️ TIME  Cleaning: {} seconds\n".format(int(elapsedTime.total_seconds())))

	# Decompile the APK File using ApkTool.
	def decompileWithApktool(self):
		"""Decompile the APK File using ApkTool."""
		try:
			print("--- ⭕ Decompiling with ApkTool.")
			# Use the specific version of Apktool jar
			command = ["java", "-jar", "/usr/local/bin/apktool.jar", "d", "-f", '-o', self.apkPath[:-4], "-q", self.apkPath]
			subprocess.run(command, check=True)
			print("--- ✅ Success.")
		except subprocess.CalledProcessError as e:
			print("--- ⚠️ [Error] PHASE 2")
			raise

	# Build a Call Graph using CallGraphExtractor (custom JAR file using FlowDroid).
	def buildCG(self):
		"""Build a Call Graph using CallGraphExtractor."""
		try:
			print("--- ⭕ Building Call Graph.")
			jarPath = "/home/marcohikari/Desktop/MarcoPhD/Projects/3_RegCheck/RegCheck2025/1_Code/1_Java/callgraphextractor/target/callgraphextractor-1.0-jar-with-dependencies.jar"
			androidPath = os.getenv("ANDROID_PATH")
			command = ["java", "-jar", jarPath, "-a", self.apkPath, "-p", androidPath]
			result = subprocess.run(command, capture_output=True, text=True)
			if result.returncode == 0:
				print("--- ✅ [Success]")
			else:
				print("--- ⚠️ [Java Error]: {}".format(result.stderr))
				raise Exception("CallGraph Construction Java Error")
		except subprocess.CalledProcessError as e:
			print("--- ⚠️ Error PHASE 3")
			raise

	# Get Nodes from Call Graph output by Flowdroid.
	def getNodesFromCG(self):
		"""Get Nodes from Call Graph output."""
		print("--- ⭕ Getting Nodes from Call Graph.")
		nodesFilePath = os.path.join(os.path.dirname(self.apkPath), self.name + "_CG_NODES", "nodes.txt")
		try:
			with open(nodesFilePath, 'r', encoding='utf-8') as file:
				self.callGraphNodes = [line.strip() for line in file.readlines()]
			print("--- #️⃣ ALL CG Nodes  : {}".format(len(self.callGraphNodes)))
		except FileNotFoundError:
			print("--- ⚠️ [Error] PHASE 3")
			raise

	# Get Smali Code from the output of ApkTool.
	def getSmaliCodeFiles(self):
		"""Get all Smali code files from the decompiled APK."""
		smaliDir = os.path.join(self.apkPath[:-4], "smali")
		self.smaliCodeFiles = []
		for root, _, files in os.walk(smaliDir):
			for file in files:
				if file.endswith(".smali"):
					self.smaliCodeFiles.append(os.path.join(root, file))

	# Get Smali Classes from Smali Code Files.
	def getSmaliClasses(self):
		"""Extract Smali classes from the code files."""
		self.smaliCodeClasses = []
		for file in self.smaliCodeFiles:
			with open(file, 'r', encoding='utf-8') as f:
				content = f.read()
				className = self._extractClassName(content)
				self.smaliCodeClasses.append({
					'className': className,
					'content': content
				})
		self.numClasses = len(self.smaliCodeClasses)

	# Filter Smali Code classes using the CG Nodes.
	def filterSmaliClassesWithCGNodes(self):
		"""Filter Smali classes based on call graph nodes."""
		if not self.callGraphNodes:
			return
		
		filteredClasses = []
		for classInfo in self.smaliCodeClasses:
			if any(node in classInfo['className'] for node in self.callGraphNodes):
				filteredClasses.append(classInfo)
		
		self.smaliCodeClasses = filteredClasses
		self.numClasses = len(self.smaliCodeClasses)

	# Delete everything related to the analyzed app.
	def deleteAll(self):
		"""Delete all temporary files."""
		try:
			print("--- 🗑️ Deleting Folders.")
			shutil.rmtree(self.apkPath[:-4])
			shutil.rmtree(os.path.join(os.path.dirname(self.apkPath), self.name + "_CG_NODES"))
		except OSError as e:
			print("--- ⚠️ Error: {}".format(e))

	# Extract class name from Smali content
	def _extractClassName(self, content: str) -> str:
		"""Extract class name from Smali content."""
		match = re.search(r'\.class public L([^;]+);', content)
		return match.group(1) if match else ""

	@staticmethod
	def get_app_paths(input_path: str, input_type: str) -> List[str]:
		"""Get list of APK paths based on input type."""
		if input_type == "local":
			return [str(p) for p in Path(input_path).glob("*.apk")]
		elif input_type == "androzoo":
			# Read CSV and return list of APK paths
			import pandas as pd
			df = pd.read_csv(input_path)
			return df['apk_path'].tolist()
		else:
			raise ValueError(f"Unsupported input type: {input_type}")

def decompileAPK(apk_path: str) -> bool:
	"""
	Decompile an APK file using apktool
	Args:
		apk_path: Path to the APK file
	Returns:
		bool: True if decompilation was successful, False otherwise
	"""
	try:
		# Get the hash from the APK filename
		apk_hash = os.path.splitext(os.path.basename(apk_path))[0]
		
		# Set up paths
		output_dir = os.path.join("0_Data", "Cache", apk_hash)
		os.makedirs(output_dir, exist_ok=True)
		
		# Run apktool
		cmd = ["apktool", "d", "-f", "-o", output_dir, apk_path]
		result = subprocess.run(cmd, capture_output=True, text=True)
		
		if result.returncode != 0:
			logger.error(f"Apktool failed: {result.stderr}")
			return False
			
		return True
		
	except Exception as e:
		logger.error(f"Error decompiling APK: {str(e)}")
		return False

def buildCallGraph(apk_hash: str) -> bool:
	"""
	Build call graph for decompiled APK
	Args:
		apk_hash: Hash of the APK file
	Returns:
		bool: True if call graph was built successfully, False otherwise
	"""
	try:
		# Set up paths
		decompiled_dir = os.path.join("0_Data", "Cache", apk_hash)
		output_dir = os.path.join("0_Data", "Results", apk_hash)
		os.makedirs(output_dir, exist_ok=True)
		
		# TODO: Implement call graph building
		# This is a placeholder for the actual implementation
		logger.info(f"Building call graph for {apk_hash}")
		return True
		
	except Exception as e:
		logger.error(f"Error building call graph: {str(e)}")
		return False

def cleanupFiles(apk_hash: str) -> None:
	"""
	Clean up temporary files after analysis
	Args:
		apk_hash: Hash of the APK file
	"""
	try:
		# Remove decompiled files
		cache_dir = os.path.join("0_Data", "Cache", apk_hash)
		if os.path.exists(cache_dir):
			shutil.rmtree(cache_dir)
			
	except Exception as e:
		logger.error(f"Error cleaning up files: {str(e)}")

def getDecompiledPath(apk_hash: str) -> str:
	"""
	Get path to decompiled APK files
	Args:
		apk_hash: Hash of the APK file
	Returns:
		str: Path to decompiled files
	"""
	return os.path.join("0_Data", "Cache", apk_hash)

def getSmaliFiles(apk_hash: str) -> list:
	"""
	Get list of Smali files from decompiled APK
	Args:
		apk_hash: Hash of the APK file
	Returns:
		list: List of paths to Smali files
	"""
	smali_files = []
	decompiled_path = getDecompiledPath(apk_hash)
	
	# Walk through all smali directories
	for root, _, files in os.walk(decompiled_path):
		if "smali" in root:
			for file in files:
				if file.endswith(".smali"):
					smali_files.append(os.path.join(root, file))
	
	return smali_files