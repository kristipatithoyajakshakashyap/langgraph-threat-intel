import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "gpt-oss:latest")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")

    VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
    ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
    SHODAN_BASE_URL = "https://api.shodan.io"

    RISK_THRESHOLD_HIGH = 80
    RISK_THRESHOLD_MEDIUM = 50
    CONFIDENCE_THRESHOLD = 0.7

    MAX_INDICATORS_PER_QUERY = 10
    API_TIMEOUT = 30


settings = Settings()
