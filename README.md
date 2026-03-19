# Threat Intelligence Research Agent

An AI-powered cybersecurity assistant built with Python, LangChain, Groq, and Streamlit. This agent can research CVEs, MITRE ATT&CK techniques, and general threat intelligence using various tools.

## Features
- **CVE Lookup**: Fetches details from the NVD API v2.
- **MITRE ATT&CK Lookup**: Queries techniques and tactics using MITRE's STIX data.
- **Web Search**: Real-time web search for threat actors, malware, and security news via SerpAPI.
- **Conversational Memory**: Remembers the context of your investigation.
- **Reasoning Transparency**: View the agent's step-by-step thought process and tool usage.

## Setup Instructions

### 1. Clone the Repository
```bash
git clone <repository-url>
cd threat-intel-agent
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Create a `.env` file in the root directory and add your API keys:
```env
GROQ_API_KEY=your_groq_api_key_here
SERPAPI_API_KEY=your_serpapi_api_key_here
```
*Note: You can get a Groq API key from [Groq Cloud](https://console.groq.com/) and a SerpAPI key from [SerpAPI](https://serpapi.com/).*

### 4. Run the Application
```bash
streamlit run app.py
```

## Example Queries
- "Tell me about CVE-2024-21762"
- "What is the MITRE ATT&CK technique T1059.001?"
- "Who is the Lazarus Group and what are their common tactics?"

## Project Structure
- `app.py`: Streamlit web interface.
- `agent/core.py`: Agent logic and executor setup.
- `agent/tools/`: Custom LangChain tools for CVE, MITRE, and Web search.
