import streamlit as st
import os
from agent.core import get_agent_executor
from dotenv import load_dotenv

load_dotenv()

# Page configuration
st.set_page_config(
    page_title="Threat Intelligence Research Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme and premium look
st.markdown("""
<style>
    .stApp {
        background-color: #0e1117;
        color: #e0e0e0;
    }
    .main-title {
        font-size: 2.5rem;
        color: #00d4ff;
        font-weight: 700;
        margin-bottom: 0.5rem;
    }
    .sub-title {
        font-size: 1.2rem;
        color: #888;
        margin-bottom: 2rem;
    }
    .investigation-card {
        background-color: #1a1c24;
        border-radius: 10px;
        padding: 20px;
        border-left: 5px solid #00d4ff;
        margin-bottom: 20px;
    }
    .stTextInput > div > div > input {
        background-color: #262730;
        color: white;
        border: 1px solid #444;
    }
    .stButton > button {
        background-color: #00d4ff;
        color: #0e1117;
        font-weight: bold;
        border-radius: 5px;
        transition: 0.3s;
    }
    .stButton > button:hover {
        background-color: #00a0cc;
        transform: translateY(-2px);
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/isometric/100/shield.png", width=80)
    st.title("Settings")
    st.write("Professional Threat Intelligence Agent powered by LangChain + Groq.")
    
    st.subheader("Available Tools")
    st.markdown("**CVE Lookup**: NVD API v2 for vulnerability details.")
    st.markdown("**MITRE ATT&CK**: Search techniques and tactics.")
    st.markdown("**Web Search**: Real-time threat actor & malware info.")
    
    st.divider()
    if st.button("Clear Chat History", use_container_width=True):
        st.session_state.chat_history = []
        st.session_state.agent_executor = get_agent_executor() # Reset memory
        st.rerun()

# Title and Subtitle
st.markdown('<h1 class="main-title">🛡️ Threat Intelligence Research Agent</h1>', unsafe_allow_html=True)
st.markdown('<p class="sub-title">Powered by LangChain + Groq + MITRE ATT&CK</p>', unsafe_allow_html=True)

# Initialize Session State
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []

if "agent_executor" not in st.session_state:
    st.session_state.agent_executor = get_agent_executor()

# User Input
query = st.text_input("Investigate a threat, CVE, or MITRE technique:", placeholder="e.g. CVE-2024-21762, T1059.001, Lazarus Group")
investigate_btn = st.button("Investigate")

if investigate_btn and query:
    with st.spinner("Agent is investigating..."):
        try:
            # Run the agent
            response = st.session_state.agent_executor.invoke({"input": query})
            
            # Store in chat history
            st.session_state.chat_history.append({
                "query": query,
                "answer": response["output"],
                "reasoning": response.get("intermediate_steps", [])
            })
            
        except Exception as e:
            st.error(f"An error occurred: {str(e)}")

# Display Chat History (Current and Past)
for i, entry in enumerate(reversed(st.session_state.chat_history)):
    st.markdown(f"### Investigation: {entry['query']}")
    
    # Reasoning Expander
    with st.expander("Agent reasoning steps", expanded=(i == 0)):
        if entry["reasoning"]:
            for step in entry["reasoning"]:
                action, observation = step
                st.markdown(f"**Action:** `{action.tool}`")
                st.markdown(f"**Action Input:** `{action.tool_input}`")
                st.markdown(f"**Observation:**")
                st.code(observation, language="text")
        else:
            st.write("No intermediate steps recorded.")
    
    # Final Answer
    st.markdown('<div class="investigation-card">', unsafe_allow_html=True)
    st.markdown(entry["answer"])
    st.markdown('</div>', unsafe_allow_html=True)
    st.divider()
