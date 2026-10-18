---
"@glinr/theauth": minor
---

Add the `@glinr/theauth/integrations` subpath with dependency free helpers for agent frameworks. `guardAiSdkTools` wraps a Vercel AI SDK tool map and `guardFunctionTool` wraps an OpenAI Agents SDK style function tool. Each call runs `authorize` first, with an optional approval retry, and a refusal comes back as a structured `ToolDenial` carrying the decision code. `createHttpGuard` calls `POST /authorize/token` for Node orchestrators such as LangGraph.js. All helpers fail closed and use structural types, so no framework is imported at runtime. Docs: `integrations/vercel-ai-sdk`, `integrations/openai-agents-sdk`, `integrations/langgraph-crewai` (includes Python REST recipes for LangGraph and CrewAI).
