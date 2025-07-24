import os
import requests
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass
import openai
from openai import OpenAI
from transformers import AutoTokenizer
import json
import time

logger = logging.getLogger(__name__)

@dataclass
class LLMConfig:
    name: str
    type: str
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None

class BaseLLMInterface:
    """Base class for LLM interfaces"""
    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Send prompt to LLM and get response
        Args:
            prompt: The prompt to send
        Returns:
            Dictionary containing response content and metrics
        """
        raise NotImplementedError("Subclasses must implement analyze()")

def create_llm_interface(config: LLMConfig) -> BaseLLMInterface:
    """
    Create appropriate LLM interface based on config
    Args:
        config: LLM configuration
    Returns:
        LLM interface instance
    """
    if config.type == "ollama":
        return OllamaInterface(config)
    elif config.type == "openai":
        return OpenAIInterface(config)
    else:
        raise ValueError(f"Unsupported LLM type: {config.type}")

class OllamaInterface(BaseLLMInterface):
    def __init__(self, config: LLMConfig):
        """Initialize Ollama interface"""
        self.base_url = config.base_url
        self.model = config.model
        self.name = config.name
        self.conversation = []

    def createConversation(self):
        self.conversation = []
        return self

    def getMessages(self):
        return self.conversation

    def sendMessage(self, message: str) -> str:
        self.conversation.append({"role": "user", "content": message})
        
        try:
            response = requests.post(
                self.api_url,
                json={
                    "model": self.model,
                    "messages": self.conversation,
                    "stream": False
                }
            )
            response.raise_for_status()
            result = response.json()
            
            assistant_message = result.get("message", {}).get("content", "")
            self.conversation.append({"role": "assistant", "content": assistant_message})
            return assistant_message
            
        except Exception as e:
            logger.error(f"Error in Ollama request: {str(e)}")
            return ""

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Send prompt to Ollama model and get response
        Args:
            prompt: The prompt to send
        Returns:
            Dictionary containing response content and metrics
        """
        try:
            # Prepare request
            url = f"{self.base_url}/api/generate"
            data = {
                "model": self.model,
                "prompt": prompt,
                "stream": False
            }
            
            # Make request
            response = requests.post(url, json=data)
            response.raise_for_status()
            
            # Parse response
            result = response.json()
            
            return {
                "content": result.get("response", ""),
                "total_tokens": result.get("total_tokens", 0)
            }
            
        except Exception as e:
            logger.error(f"Error calling Ollama API: {str(e)}")
            return {
                "content": f"Error: {str(e)}",
                "total_tokens": 0
            }

class OpenAIInterface(BaseLLMInterface):
    def __init__(self, config: LLMConfig):
        self.name = config.name
        self.model = config.model
        self.api_key = config.api_key
        self.client = openai.OpenAI(api_key=self.api_key)

    def sendMessage(self, message: str) -> str:
        self.conversation.append({"role": "user", "content": message})
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.conversation
            )
            
            assistant_message = response.choices[0].message.content
            self.conversation.append({"role": "assistant", "content": assistant_message})
            return assistant_message
            
        except Exception as e:
            logger.error(f"--- ⚠️ Error in OpenAI request: {str(e)}")
            return ""

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Send prompt to OpenAI model and get response
        Args:
            prompt: The prompt to send
        Returns:
            Dictionary containing response content and metrics
        """
        try:
            # Make request
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}]
            )
            
            # Get first choice content
            content = response.choices[0].message.content if response.choices else ""
            
            return {
                "content": content,
                "total_tokens": response.usage.total_tokens if hasattr(response, 'usage') else 0
            }
            
        except Exception as e:
            logger.error(f"Error calling OpenAI API: {str(e)}")
            return {
                "content": f"Error: {str(e)}",
                "total_tokens": 0
            }

class LlamaTokenizer:
    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained("meta-llama/Llama-2-7b-chat-hf")

    def getNumTokens(self, text: str) -> int:
        return len(self.tokenizer.encode(text))