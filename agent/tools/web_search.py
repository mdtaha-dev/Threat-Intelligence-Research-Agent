import os
from langchain_community.utilities import SerpAPIWrapper
from langchain.tools import tool
from dotenv import load_dotenv

load_dotenv()

@tool
def web_search(query: str) -> str:
    """
    Search the web for general threat intelligence, threat actors, or malware information using SerpAPI.
    Returns the top 3 search results summarized.
    """
    search = SerpAPIWrapper()
    results = search.run(query)
    # The run() method returns a string summary, but we can also use search.results(query) for structured data
    # Let's keep it simple and use the run() result or format it.
    return str(results)
