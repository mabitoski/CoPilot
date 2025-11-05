import asyncio
import json
import os
import re
import time
from enum import Enum
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from fastapi import HTTPException
from loguru import logger
import openai
from openai.error import OpenAIError

from app.connectors.wazuh_indexer.schema.alerts import AlertsSearchBody
from app.connectors.wazuh_indexer.services.alerts import collect_and_aggregate_alerts
from app.integrations.copilot_mcp.schema.copilot_mcp import MCPQueryRequest
from app.integrations.copilot_mcp.schema.copilot_mcp import MCPQueryResponse
from app.integrations.copilot_mcp.schema.copilot_mcp import MCPServerType
from app.integrations.copilot_mcp.schema.copilot_mcp import StructuredAgentResponse


class MCPServiceType(str, Enum):
    """Enumeration of MCP service deployment types"""

    LOCAL = "local"
    CLOUD = "cloud"


class MCPServerConfig:
    """Configuration for MCP server endpoints"""

    def __init__(self, service_type: MCPServiceType, endpoint: str):
        self.service_type = service_type
        self.endpoint = endpoint


class MCPService:
    """Service for handling MCP queries with modular server routing"""

    # Base URLs for different service types
    _BASE_URLS = {
        MCPServiceType.LOCAL: "http://copilot-mcp/mcp",
        MCPServiceType.CLOUD: "https://mcp.socfortress.co/query",
    }

    # Define the mapping of MCP server types to their configurations
    _SERVER_CONFIGS: Dict[MCPServerType, MCPServerConfig] = {
        # Local services
        MCPServerType.WAZUH_INDEXER: MCPServerConfig(MCPServiceType.LOCAL, "opensearch-query"),
        MCPServerType.WAZUH_MANAGER: MCPServerConfig(MCPServiceType.LOCAL, "wazuh-query"),
        MCPServerType.COPILOT: MCPServerConfig(MCPServiceType.LOCAL, "mysql-query"),
        MCPServerType.VELOCIRAPTOR: MCPServerConfig(MCPServiceType.LOCAL, "velociraptor-query"),
        # Cloud services
        MCPServerType.THREAT_INTEL: MCPServerConfig(MCPServiceType.CLOUD, "threat_intel"),
        MCPServerType.CYBER_NEWS: MCPServerConfig(MCPServiceType.CLOUD, "cyber_news"),
        MCPServerType.KNOWLEDGEBASE: MCPServerConfig(MCPServiceType.CLOUD, "knowledgebase"),
        MCPServerType.ATTACK_SURFACE: MCPServerConfig(MCPServiceType.CLOUD, "attack_surface"),
    }

    @classmethod
    def get_server_config(cls, mcp_server: MCPServerType) -> MCPServerConfig:
        """
        Get the configuration for a specific MCP server type.

        Args:
            mcp_server: The MCP server type

        Returns:
            MCPServerConfig: The configuration for the server

        Raises:
            ValueError: If the server type is not supported
        """
        config = cls._SERVER_CONFIGS.get(mcp_server)
        if not config:
            raise ValueError(f"Unsupported MCP server type: {mcp_server}")
        return config

    @classmethod
    def build_full_url(cls, mcp_server: MCPServerType) -> str:
        """
        Build the full URL for a specific MCP server type.

        Args:
            mcp_server: The MCP server type

        Returns:
            str: The full URL for the server endpoint
        """
        config = cls.get_server_config(mcp_server)
        base_url = cls._BASE_URLS[config.service_type]
        return f"{base_url}/{config.endpoint}"

    @classmethod
    def is_cloud_service(cls, mcp_server: MCPServerType) -> bool:
        """
        Check if the MCP server is a cloud service.

        Args:
            mcp_server: The MCP server type

        Returns:
            bool: True if it's a cloud service, False if local
        """
        config = cls.get_server_config(mcp_server)
        return config.service_type == MCPServiceType.CLOUD

    @classmethod
    async def execute_query(cls, data: MCPQueryRequest, license_key: Optional[str] = None) -> MCPQueryResponse:
        """
        Execute a chatbot query using OpenAI while preserving the MCP response contract.
        """
        del license_key  # Legacy parameter retained for compatibility.

        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.error("OPENAI_API_KEY environment variable not configured.")
            return MCPQueryResponse(
                message="OpenAI integration is not configured.",
                success=False,
                result=None,
                structured_result=None,
                execution_time=0.0,
            )

        model = os.getenv("OPENAI_MODEL", "gpt-4o")
        openai.api_key = api_key

        system_prompt = (
            "You are the SOCFORTRESS CoPilot assistant. Provide clear, actionable responses in Markdown. "
            "When relevant, include bullet lists or tables. Use concise explanations tailored to SOC analysts. "
            "When operational context is provided, ground your answers in that data and state when information is unavailable. "
            "Always return valid JSON with the keys: response (string) and optional thinking_process (string)."
        )

        context_text = ""
        if data.mcp_server in {
            MCPServerType.COPILOT,
            MCPServerType.WAZUH_INDEXER,
            MCPServerType.WAZUH_MANAGER,
        }:
            context_text = await cls._build_soc_context()

        server_context = (
            f"The user selected the '{data.mcp_server.value}' knowledge domain. "
            "Use this as context to shape your answer, but you do not need to access external tools."
        )
        verbose_hint = "The user requested verbose output with more detailed reasoning." if data.verbose else ""

        context_section = ""
        if context_text:
            context_section = f"Operational context (last 24h):\n{context_text}\n\n"

        user_prompt = (
            f"{context_section}"
            f"{server_context} {verbose_hint}\n\n"
            "User question:\n"
            f"{data.input}"
        ).strip()

        def _perform_openai_call() -> Dict[str, Any]:
            completion = openai.ChatCompletion.create(
                model=model,
                temperature=0.3,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return completion

        start_time = time.perf_counter()
        try:
            completion = await asyncio.to_thread(_perform_openai_call)
        except OpenAIError as exc:
            logger.error(f"OpenAI API error while handling chatbot query: {exc}")
            return MCPQueryResponse(
                message=f"OpenAI API error: {exc}",
                success=False,
                result=None,
                structured_result=None,
                execution_time=0.0,
            )
        except Exception as exc:  # pragma: no cover
            logger.error(f"Unexpected error during OpenAI chatbot request: {exc}")
            return MCPQueryResponse(
                message="Unexpected error during OpenAI processing.",
                success=False,
                result=None,
                structured_result=None,
                execution_time=0.0,
            )

        execution_time = time.perf_counter() - start_time

        try:
            content = completion["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            logger.error(f"Unexpected OpenAI response format: {completion}")
            return MCPQueryResponse(
                message="OpenAI response format is invalid.",
                success=False,
                result=None,
                structured_result=None,
                execution_time=execution_time,
            )

        structured_result = None
        result: Optional[Any] = None

        try:
            parsed = cls._parse_openai_json_payload(content)
            structured_result = StructuredAgentResponse(
                response=parsed["response"],
                thinking_process=parsed.get("thinking_process"),
            )
            result = {
                "response": structured_result.response,
                "thinking_process": structured_result.thinking_process,
            }
        except ValueError:
            logger.debug("OpenAI response was not JSON-formatted; returning raw content.")
            result = content

        return MCPQueryResponse(
            message="Query processed successfully.",
            success=True,
            result=result,
            structured_result=structured_result,
            execution_time=execution_time,
        )

    @classmethod
    async def _build_soc_context(cls, timerange: str = "24h", top_n: int = 5) -> str:
        """
        Build a concise SOC context summary to ground chatbot responses.
        """
        search_body = AlertsSearchBody(timerange=timerange, size=top_n)

        try:
            (
                host_top,
                host_total,
            ), (
                rule_top,
                _,
            ), (
                source_top,
                _,
            ) = await asyncio.gather(
                cls._aggregate_field(["agent_name"], search_body, top_n),
                cls._aggregate_field(["rule_description"], search_body, top_n),
                cls._aggregate_field(["syslog_type"], search_body, top_n),
            )
        except HTTPException as exc:
            logger.warning(f"Failed to gather SOC context from Wazuh Indexer: {exc.detail}")
            return ""
        except Exception as exc:  # pragma: no cover
            logger.warning(f"Unexpected error while gathering SOC context: {exc}")
            return ""

        if host_total == 0 and not (rule_top or source_top):
            return ""

        lines = []
        if host_total:
            lines.append(f"- Total alerts observed: {host_total}")

        if host_top:
            lines.append("- Top hosts by alert volume:")
            for label, count in host_top:
                lines.append(f"  • {label}: {count}")

        if rule_top:
            lines.append("- Top rules triggered:")
            for label, count in rule_top:
                lines.append(f"  • {label}: {count}")

        if source_top:
            lines.append("- Top alert sources:")
            for label, count in source_top:
                lines.append(f"  • {label}: {count}")

        return "\n".join(lines)

    @staticmethod
    def _parse_openai_json_payload(raw_content: str) -> Dict[str, Any]:
        """
        Extract JSON payload from OpenAI response content, handling Markdown fences.

        Raises:
            ValueError: If payload cannot be parsed or lacks required fields.
        """
        if not isinstance(raw_content, str):
            raise ValueError("OpenAI response content must be a string.")

        text = raw_content.strip()
        fence_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.S)
        if fence_match:
            text = fence_match.group(1)

        decoder = json.JSONDecoder(strict=False)
        parsed = decoder.decode(text)

        if not isinstance(parsed, dict):
            raise ValueError("OpenAI response must be a JSON object.")

        if "response" not in parsed or parsed["response"] in (None, ""):
            raise ValueError("OpenAI response missing 'response' field.")

        parsed["response"] = str(parsed["response"])
        if parsed.get("thinking_process") is not None:
            parsed["thinking_process"] = str(parsed["thinking_process"])

        return parsed

    @staticmethod
    async def _aggregate_field(
        field_names: List[str],
        search_body: AlertsSearchBody,
        top_n: int,
    ) -> Tuple[List[Tuple[str, int]], int]:
        """
        Aggregate alerts by the given field names and return the top results.
        """
        try:
            raw_counts = await collect_and_aggregate_alerts(field_names, search_body)
        except Exception as exc:
            logger.debug(f"Failed to aggregate field {field_names}: {exc}")
            return [], 0

        total = sum(raw_counts.values())
        formatted: list[tuple[str, int]] = []
        for composite_key, count in raw_counts.items():
            label_parts = [
                str(part).strip()
                for part in composite_key
                if part not in (None, "", "None", "null")
            ]
            label = " / ".join(label_parts) if label_parts else "Unknown"
            formatted.append((label, count))

        formatted.sort(key=lambda item: item[1], reverse=True)
        return formatted[:top_n], total

    @classmethod
    def add_local_service(cls, server_type: MCPServerType, endpoint: str) -> None:
        """
        Add a new local MCP service.

        Args:
            server_type: The MCP server type enum
            endpoint: The endpoint path for the local service
        """
        cls._SERVER_CONFIGS[server_type] = MCPServerConfig(MCPServiceType.LOCAL, endpoint)

    @classmethod
    def add_cloud_service(cls, server_type: MCPServerType, endpoint: str) -> None:
        """
        Add a new cloud MCP service.

        Args:
            server_type: The MCP server type enum
            endpoint: The endpoint path for the cloud service
        """
        cls._SERVER_CONFIGS[server_type] = MCPServerConfig(MCPServiceType.CLOUD, endpoint)

    @classmethod
    def get_service_info(cls) -> Dict[str, Dict[str, str]]:
        """
        Get information about all configured services.

        Returns:
            Dict containing service information grouped by type
        """
        local_services = {}
        cloud_services = {}

        for server_type, config in cls._SERVER_CONFIGS.items():
            service_info = {"endpoint": config.endpoint, "full_url": cls.build_full_url(server_type)}

            if config.service_type == MCPServiceType.LOCAL:
                local_services[server_type.value] = service_info
            else:
                cloud_services[server_type.value] = service_info

        return {"local": local_services, "cloud": cloud_services}


# Convenience function to maintain backward compatibility
async def post_to_copilot_mcp(data: MCPQueryRequest) -> MCPQueryResponse:
    """
    Send a POST request to the appropriate copilot-mcp endpoint based on server type.

    This function maintains backward compatibility while using the new modular service.

    Args:
        data: The MCP query request

    Returns:
        MCPQueryResponse: The response from the MCP server
    """
    return await MCPService.execute_query(data)
