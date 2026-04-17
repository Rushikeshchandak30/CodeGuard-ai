# ⚠️ TEST FILE — CodeGuard AI v8.0 Secrets Scanner
# Every variable below should trigger a CG_SECRET_* HIGH/CRITICAL finding.
# Open this file in Windsurf with CodeGuard installed — expect 20+ diagnostics.
# NEVER commit real credentials. All values here are fake test strings.

import openai
import anthropic
import boto3

# ── AI Providers ──────────────────────────────────────────────────────────────

# OpenAI (CG_SECRET_001)
OPENAI_API_KEY = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghijklmnopqrstuvwxyz12"

# Anthropic Claude (CG_SECRET_002)
ANTHROPIC_API_KEY = "sk-ant-api03-FAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEY"

# HuggingFace (CG_SECRET_003)
HF_TOKEN = "hf_FaKeToKeNfAkEtOkEnFaKeToKeNfAkEtOkEn"

# Replicate (CG_SECRET_004)
REPLICATE_API_TOKEN = "r8_FaKeRePlIcAtEtOkEnFaKeRePlIcAtEtOkEn1234"

# Groq (CG_SECRET_005)
GROQ_API_KEY = "gsk_FaKeGrOqApIkEyFaKeGrOqApIkEyFaKeGrOqApIkEy"

# Cohere (CG_SECRET_006)
COHERE_API_KEY = "FaKeCohEreApIkEyFaKeCohEreApIkEyFaKe1234"

# Mistral / Codestral (CG_SECRET_007)
MISTRAL_API_KEY = "FaKeMiStRaLkEyFaKeMiStRaLkEyFaKeMiStRaLkEy"

# Perplexity (CG_SECRET_008)
PERPLEXITY_API_KEY = "pplx-FaKeKeYfAkEkEyFaKeKeYfAkEkEyFaKeKeYfAkEkEy"

# xAI / Grok (CG_SECRET_009)
XAI_API_KEY = "xai-FaKeXaIkEyFaKeXaIkEyFaKeXaIkEyFaKeXaIkEy"

# Together AI (CG_SECRET_010)
TOGETHER_API_KEY = "FaKeToGeThErApIkEyFaKeToGeThErApIkEy1234567890ab"

# DeepSeek (CG_SECRET_011)
DEEPSEEK_API_KEY = "sk-FaKeDeEpSeEkApIkEy1234567890abcdefghijklmnop"

# Fireworks AI (CG_SECRET_012)
FIREWORKS_API_KEY = "fw_FaKeFiReWoRkSkEyFaKeFiReWoRkSkEyFaKe"

# LangSmith (CG_SECRET_013)
LANGSMITH_API_KEY = "lsv2_pt_FaKeLaNgSmItHkEyFaKeLaNgSmItHkEy_FaKe1234"

# Pinecone (CG_SECRET_014)
PINECONE_API_KEY = "FaKePiNeCoNeApIkEy-1234-5678-abcd-efghijklmnop"

# ── Cloud Providers ───────────────────────────────────────────────────────────

# AWS (CG_SECRET_020)
AWS_ACCESS_KEY_ID     = "AKIAFAKEKEYIDEXAMPLE"
AWS_SECRET_ACCESS_KEY = "FaKeAwSsEcReTkEyFaKeAwSsEcReTkEyFaKeAwS1"

# Google Cloud service account JSON key (CG_SECRET_021)
GCP_SERVICE_ACCOUNT = '{"type":"service_account","project_id":"fake-project","private_key_id":"abc123","private_key":"-----BEGIN RSA PRIVATE KEY-----\\nFAKE\\n-----END RSA PRIVATE KEY-----\\n","client_email":"fake@fake-project.iam.gserviceaccount.com"}'

# Azure Storage connection string (CG_SECRET_022)
AZURE_STORAGE_CONNECTION = "DefaultEndpointsProtocol=https;AccountName=fakestorageacct;AccountKey=FaKeAzUrEsToRaGeKeYfAkEaZuReStOrAgEkEy==;EndpointSuffix=core.windows.net"

# DigitalOcean PAT (CG_SECRET_023)
DO_TOKEN = "dop_v1_FaKeDigItAlOcEaNpAtFaKeDigItAlOcEaNpAt1234567890abcdef"

# ── CI / Dev ──────────────────────────────────────────────────────────────────

# GitHub PAT (CG_SECRET_030)
GITHUB_TOKEN = "ghp_FaKeGiThUbPaT1234567890abcdefghijklmno"

# GitLab PAT (CG_SECRET_031)
GITLAB_TOKEN = "glpat-FaKeGiTlAbToKeNfAkEgItLaBtOkEn1234"

# Docker Hub PAT (CG_SECRET_032)
DOCKER_TOKEN = "dckr_pat_FaKeDoCkErHuBtOkEnFaKe1234567890ab"

# CircleCI token (CG_SECRET_033)
CIRCLECI_TOKEN = "FaKeCiRcLeCiToKeN1234567890abcdefghijklmnopqrstuvwxyz"

# ── Payment ───────────────────────────────────────────────────────────────────

# Stripe (CG_SECRET_040)
STRIPE_SECRET_KEY = "sk_live_FaKeStRiPeKeYfAkEsTrIpEkEy1234567890abcde"

# Stripe publishable (not secret but still flagged in server-side code)
STRIPE_PK = "pk_live_FaKeStRiPePublishableKeyFaKe1234567890"

# PayPal (CG_SECRET_041)
PAYPAL_CLIENT_SECRET = "FaKePayPaLsEcReTfAkEpAyPaLsEcReT1234567890AB"

# Square (CG_SECRET_042)
SQUARE_ACCESS_TOKEN = "EAAAFaKeSqUaReToKeNfAkEsQuArEtOkEn1234567890"

# ── Misc ──────────────────────────────────────────────────────────────────────

# Twilio (CG_SECRET_050)
TWILIO_AUTH_TOKEN = "FaKeTwIlIoToKeNfAkEtWiLiOtOkEn1234567890abcdef"

# Slack (CG_SECRET_051)
SLACK_BOT_TOKEN = "xoxb-FaKeSlAcKtOkEn-FaKeSlAcKtOkEn-FaKeSlAcKtOkEn"

# Shopify (CG_SECRET_052)
SHOPIFY_ACCESS_TOKEN = "shpat_FaKeShOpIfYtOkEnFaKeShOpIfYtOkEn1234"

# Discord bot token (CG_SECRET_053)
DISCORD_BOT_TOKEN = "FaKeDiscordBotToken.FaKe.FaKeDisCordBoTtOkEnFaKe1234"

# Datadog (CG_SECRET_054)
DATADOG_API_KEY = "FaKeDaTaDogApIkEyFaKeDaTaDogApIkEy12345678"

# ── Usage (would normally be after safe config load) ─────────────────────────

client = openai.OpenAI(api_key=OPENAI_API_KEY)
s3 = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID,
                  aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
