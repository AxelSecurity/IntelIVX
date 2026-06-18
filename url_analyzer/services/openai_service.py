import asyncio
import json
import logging
import re

from azure.ai.projects import AIProjectClient
from azure.identity import ClientSecretCredential, DefaultAzureCredential

from url_analyzer.config import settings
from url_analyzer.models.job import PlaywrightResult, URLVerdict

logger = logging.getLogger(__name__)


def _build_credential():
    """
    Seleziona la credential Azure AD in base alla configurazione:
    - Se AZURE_TENANT_ID / CLIENT_ID / CLIENT_SECRET sono impostati → ClientSecretCredential
      (service principal: ideale per Docker / ambienti non interattivi)
    - Altrimenti → DefaultAzureCredential
      (az login locale, Managed Identity su Azure, ecc.)
    """
    if settings.azure_tenant_id and settings.azure_client_id and settings.azure_client_secret:
        logger.info("Foundry auth: ClientSecretCredential (service principal)")
        return ClientSecretCredential(
            tenant_id=settings.azure_tenant_id,
            client_id=settings.azure_client_id,
            client_secret=settings.azure_client_secret,
        )
    logger.info("Foundry auth: DefaultAzureCredential")
    return DefaultAzureCredential()


_ANALYZE_PREFIX = "TASK: ANALYZE_URL\n\nAnalyze the following URL browser analysis:\n\n"

_SYNTHESIZE_PREFIX = (
    "TASK: SYNTHESIZE_CHAIN\n\n"
    "Synthesize the list of verdicts below into a single final verdict.\n"
    "Rules:\n"
    "- If ANY verdict is malicious → final verdict is malicious.\n"
    "- If ANY verdict is suspicious and none malicious → final verdict is suspicious.\n"
    "- Only safe if ALL verdicts are safe.\n"
    "- recommended_action: strictest across chain (block > quarantine > allow).\n"
    "- url field must be the first URL in the list.\n"
    "- Combine risk_indicators from all hops, deduplicated.\n\n"
    "Verdicts:\n\n"
)


def _extract_json(text: str) -> dict:
    """
    Estrae il primo oggetto JSON dalla risposta dell'agente.
    Gestisce: blocco ```json {...} ```, JSON grezzo, JSON embedded nel testo.
    """
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        return json.loads(m.group(1))
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        return json.loads(m.group(0))
    raise ValueError(f"No JSON found in agent response: {text[:300]}")


class FoundryAgentService:
    def __init__(self) -> None:
        project_client = AIProjectClient(
            endpoint=settings.foundry_endpoint,
            credential=_build_credential(),
        )
        # get_openai_client() configura automaticamente endpoint e API version Foundry
        self._oai = project_client.get_openai_client()
        self._agent_name = settings.foundry_agent_name
        self._agent_version = settings.foundry_agent_version

    def _call_agent_sync(self, user_message: str) -> dict:
        """
        Chiama l'agente Foundry via Responses API (singolo turno, senza thread).
        """
        response = self._oai.responses.create(
            input=[{"role": "user", "content": user_message}],
            extra_body={
                "agent_reference": {
                    "name": self._agent_name,
                    "version": self._agent_version,
                    "type": "agent_reference",
                }
            },
        )
        raw_text = response.output_text
        logger.debug("Foundry agent response: %s", raw_text[:500])
        return _extract_json(raw_text)

    async def _call_agent(self, user_message: str) -> dict:
        """Wrapper async: esegue la chiamata sincrona in un thread pool separato."""
        return await asyncio.to_thread(self._call_agent_sync, user_message)

    async def analyze(self, playwright_result: PlaywrightResult) -> URLVerdict:
        payload = playwright_result.model_dump(exclude={"screenshot_base64"})
        user_message = _ANALYZE_PREFIX + json.dumps(payload, indent=2)

        data = await self._call_agent(user_message)
        verdict = URLVerdict(**data)
        verdict.ssl_info = playwright_result.ssl_info
        return verdict

    async def synthesize_chain(self, verdicts: list[URLVerdict]) -> URLVerdict:
        payload = [v.model_dump(exclude={"chain_verdicts"}) for v in verdicts]
        user_message = _SYNTHESIZE_PREFIX + json.dumps(payload, indent=2)

        data = await self._call_agent(user_message)
        data["url"] = verdicts[0].url
        return URLVerdict(**data)


# Singleton — stessa variabile importata da workers/analyzer.py e main.py
openai_service = FoundryAgentService()
