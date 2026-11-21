from functools import lru_cache

from strands import Agent
from strands.agent.conversation_manager.null_conversation_manager import NullConversationManager
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from model.load import load_model
from parse import parse_payload
from memory.session import get_memory_session_manager
from ec2_tools import EC2_TOOLS

DEFAULT_SYSTEM_PROMPT = """You are EC2 Doctor, an assistant that troubleshoots and reviews
Amazon EC2 instances in the ap-south-1 (Mumbai) region.

Rules:
- Always call the tools to collect evidence before you conclude anything. Never guess.
- You have read-only access. You cannot change anything; you recommend, a human applies.
- If a tool returns an error, say what failed and what permission or input is missing.
- If the user gives no instance ID, ask for it.

Answer in this format:
1. Summary: one or two lines.
2. Findings: a table with the columns Finding | Severity (High/Medium/Low) | Evidence.
3. Fixes: for each finding, the exact AWS CLI command, with --region ap-south-1.
   Warn clearly before any command that causes downtime or data loss.
"""

# The model can only use what we hand it here: six read-only EC2 tools.
tools = list(EC2_TOOLS)

def _make_conversation_manager():
    return NullConversationManager()

@lru_cache(maxsize=128)
def _get_agent(session_id: str, actor_id: str) -> Agent:
    """Given a session_id and actor_id, return or construct the corresponding Strands agent.
    Note: caching helps avoid repeated identity fetches on non-bedrock model loads
    and supports in-memory session management for local dev."""
    return Agent(
        model=load_model(),
        session_manager=get_memory_session_manager(session_id, actor_id),
        conversation_manager=_make_conversation_manager(),
        system_prompt=DEFAULT_SYSTEM_PROMPT,
        tools=tools,
    )

def create_app():
    app = BedrockAgentCoreApp()
    log = app.logger

    @app.entrypoint
    async def invoke(payload, context):
        log.info("Invoking Agent.....")

        session_id = getattr(context, "session_id", None) or "default-session"
        prompt, actor_id = parse_payload(payload)

        log.info(f"Invoking with session_id={session_id} and actor_id={actor_id}")
        agent = _get_agent(session_id, actor_id)

        async for event in agent.stream_async(prompt):
            if not isinstance(event, dict) or "event" not in event:
                continue
            cbs = event["event"].get("contentBlockStart")
            if cbs is not None and not cbs.get("start"):
                continue
            yield event

    return app

app = create_app()
if __name__ == "__main__":
    app.run()
