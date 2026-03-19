import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain.agents import AgentExecutor, create_react_agent
from langchain.memory import ConversationBufferWindowMemory
from langchain import hub
from agent.tools.cve_lookup import cve_lookup
from agent.tools.mitre_lookup import mitre_lookup
from agent.tools.web_search import web_search

load_dotenv()

def get_agent_executor():
    """Set up and return the AgentExecutor."""
    
    # Initialize the LLM
    llm = ChatGroq(
        model="llama-3.3-70b-versatile",
        api_key=os.getenv("GROQ_API_KEY"),
        temperature=0
    )
    
    # List of tools
    tools = [cve_lookup, mitre_lookup, web_search]
    
    # Custom prompt for the Threat Intelligence Agent
    prompt = hub.pull("hwchase17/react")
    
    # Add custom instructions to the prompt
    # The default react prompt uses {tools}, {tool_names}, {input}, {agent_scratchpad}
    # We can prepend our system instructions to the prefix of the prompt template
    
    system_instructions = (
        "You are a professional Cyber Security Threat Intelligence Assistant.\n"
        "Your goal is to provide synthesized, accurate, and actionable threat intelligence.\n"
        "Instructions:\n"
        "- For CVE IDs (e.g., CVE-2024-1234), use the cve_lookup tool first.\n"
        "- For Technique IDs (e.g., T1059) or Tactic names, use the mitre_lookup tool first.\n"
        "- For general information about threat actors, malware, or current news, use the web_search tool.\n"
        "- Always synthesize a final response that includes: Threat Summary, Severity/Impact, Affected Systems, and Recommended Mitigations.\n"
        "- If you cannot find information with one tool, try another if relevant.\n"
        "- Maintain a professional, technical, and concise tone.\n"
    )
    
    template = system_instructions + "\n" + "Chat History: {chat_history}\n" + prompt.template
    prompt.template = template

    # Memory
    memory = ConversationBufferWindowMemory(
        k=5, 
        memory_key="chat_history", 
        input_key="input",
        output_key="output"
    )
    
    # Create the ReAct agent
    agent = create_react_agent(llm, tools, prompt)
    
    # Agent Executor
    agent_executor = AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=True,
        handle_parsing_errors=True,
        max_iterations=5,
        memory=memory,
        return_intermediate_steps=True # Crucial for Streamlit UI "reasoning steps"
    )
    
    return agent_executor
