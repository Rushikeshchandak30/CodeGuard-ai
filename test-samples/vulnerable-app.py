# Sample Python file to test CodeGuard AI extension
# Open this file in the Extension Development Host to see diagnostics

# Known vulnerable packages (should trigger CVE warnings)
import requests          # Check for known vulns
from flask import Flask  # Check for known vulns
import django            # Has had several CVEs
import urllib3           # Has had CVEs

# Hallucinated / non-existent packages (should trigger red squiggly)
import ai_super_helper_nonexistent
from fake_ml_library_xyz import train_model

# AI-generated plausible-sounding but non-existent PyPI packages   # Sounds like flask plugin - fake
import django_rest_helpers            # Sounds like DRF utility - fake
import pandas_dataframe_utils         # Sounds like pandas extension - fake
import numpy_array_toolkit            # Sounds like numpy utility - fake
import sklearn_model_helpers          # Sounds like scikit-learn plugin - fake
from sqlalchemy_orm_utils import Base # Sounds like SQLAlchemy extension - fake
from fastapi_auth_middleware import AuthMiddleware  # Sounds like FastAPI plugin - fake
import pydantic_schema_validator      # Sounds like pydantic extension - fake
import celery_task_manager            # Sounds like celery plugin - fake
import boto3_s3_helper                # Sounds like boto3 utility - fake
import jwt_token_utils                # Sounds like PyJWT wrapper - fake
import redis_cache_helper             # Sounds like redis-py wrapper - fake
from tensorflow_model_utils import load  # Sounds like TF utility - fake
import torch_training_helper          # Sounds like PyTorch utility - fake
import openai_response_parser         # Sounds like openai wrapper - fake
from langchain_document_helper import chunk_text  # Sounds like LangChain util - fake
import pytest_mock_helper             # Sounds like pytest plugin - fake
import aiohttp_request_utils          # Sounds like aiohttp extension - fake
from cryptography_utils import encrypt_aes  # Sounds like cryptography wrapper - fake
import logging_config_helper          # Sounds like logging utility - fake

# Standard library (should be ignored — no warnings)
import os
import sys
import json
import pathlib
import hashlib
import datetime

# Safe third-party
import numpy
from pandas import DataFrame
