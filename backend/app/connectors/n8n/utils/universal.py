from typing import Any
from typing import Dict
from typing import Optional

import requests
from fastapi import HTTPException
from loguru import logger

from app.connectors.utils import get_connector_info_from_db
from app.db.db_session import get_db_session

DEFAULT_CONNECTOR_NAME = "N8N"
DEFAULT_TIMEOUT = 20


def _normalise_endpoint(endpoint: str) -> str:
    if not endpoint.startswith("/"):
        return f"/{endpoint}"
    return endpoint


def _build_headers(attributes: Dict[str, Any]) -> Dict[str, str]:
    headers = {
        "X-N8N-API-KEY": attributes.get("connector_api_key", ""),
        "Content-Type": "application/json",
    }
    if not headers["X-N8N-API-KEY"]:
        raise HTTPException(status_code=400, detail="N8N connector API key is missing.")
    return headers


def _build_base_url(attributes: Dict[str, Any]) -> str:
    base_url = attributes.get("connector_url", "").rstrip("/")
    if not base_url:
        raise HTTPException(status_code=400, detail="N8N connector URL is missing.")
    return base_url


async def verify_n8n_credentials(attributes: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify the connection against the N8N instance by fetching the workflow list.
    """
    logger.info(
        "Verifying the N8N connection to {}", attributes.get("connector_url")
    )
    try:
        headers = _build_headers(attributes)
        response = requests.get(
            f"{_build_base_url(attributes)}/rest/workflows",
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
            verify=False,
        )
        if response.status_code == 200:
            logger.info(
                "Successfully connected to N8N instance at {}",
                attributes.get("connector_url"),
            )
            return {
                "connectionSuccessful": True,
                "message": "N8N connection successful",
            }
        logger.error(
            "Connection to {} failed with status {}: {}",
            attributes.get("connector_url"),
            response.status_code,
            response.text,
        )
        return {
            "connectionSuccessful": False,
            "message": f"Connection to {attributes.get('connector_url')} failed with error: {response.text}",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Connection to {} failed with error: {}",
            attributes.get("connector_url"),
            exc,
        )
        return {
            "connectionSuccessful": False,
            "message": f"Connection to {attributes.get('connector_url')} failed with error: {exc}",
        }


async def verify_n8n_connection(connector_name: str = DEFAULT_CONNECTOR_NAME) -> Optional[Dict[str, Any]]:
    """
    Returns whether the connection to the N8N service is successful.
    """
    logger.info("Validating N8N connector configuration for {}", connector_name)
    async with get_db_session() as session:
        attributes = await get_connector_info_from_db(connector_name, session)
    if attributes is None:
        logger.error("No N8N connector named {} found in the database", connector_name)
        return None
    return await verify_n8n_credentials(attributes)


async def send_get_request(
    endpoint: str,
    params: Optional[Dict[str, Any]] = None,
    connector_name: str = DEFAULT_CONNECTOR_NAME,
) -> Dict[str, Any]:
    """
    Sends a GET request to the N8N service.
    """
    logger.info("Sending GET request to {}", endpoint)
    async with get_db_session() as session:
        attributes = await get_connector_info_from_db(connector_name, session)
    if attributes is None:
        logger.error("No N8N connector found in the database")
        return {"success": False, "message": "N8N connector not configured"}
    try:
        response = requests.get(
            f"{_build_base_url(attributes)}{_normalise_endpoint(endpoint)}",
            headers=_build_headers(attributes),
            params=params,
            timeout=DEFAULT_TIMEOUT,
            verify=False,
        )
        response.raise_for_status()
        logger.info("GET {} returned status {}", endpoint, response.status_code)
        return {
            "data": response.json(),
            "success": True,
            "message": "Successfully retrieved data",
        }
    except HTTPException:
        raise
    except requests.HTTPError as exc:
        error_response = exc.response
        status_code = error_response.status_code if error_response else 500
        detail = error_response.text if error_response else str(exc)
        logger.error("Failed GET request to {}: {}", endpoint, detail)
        raise HTTPException(status_code=status_code, detail=detail)
    except Exception as exc:
        logger.error("Failed GET request to {} with error: {}", endpoint, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send GET request to {endpoint} with error: {exc}",
        )


async def send_post_request(
    endpoint: str,
    data: Optional[Dict[str, Any]] = None,
    connector_name: str = DEFAULT_CONNECTOR_NAME,
) -> Dict[str, Any]:
    """
    Sends a POST request to the N8N service.
    """
    logger.info("Sending POST request to {}", endpoint)
    async with get_db_session() as session:
        attributes = await get_connector_info_from_db(connector_name, session)
    if attributes is None:
        logger.error("No N8N connector found in the database")
        return {"success": False, "message": "N8N connector not configured"}
    try:
        response = requests.post(
            f"{_build_base_url(attributes)}{_normalise_endpoint(endpoint)}",
            headers=_build_headers(attributes),
            json=data or {},
            timeout=DEFAULT_TIMEOUT,
            verify=False,
        )
        logger.info("POST {} returned status {}", endpoint, response.status_code)
        if response.status_code == 204:
            return {"success": True, "data": None, "message": "Successfully completed request with no content"}
        response.raise_for_status()
        return {
            "data": response.json(),
            "success": True,
            "message": "Successfully processed request",
        }
    except HTTPException:
        raise
    except requests.HTTPError as exc:
        error_response = exc.response
        status_code = error_response.status_code if error_response else 500
        detail = error_response.text if error_response else str(exc)
        logger.error("Failed POST request to {}: {}", endpoint, detail)
        raise HTTPException(status_code=status_code, detail=detail)
    except Exception as exc:
        logger.error("Failed POST request to {} with error: {}", endpoint, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send POST request to {endpoint} with error: {exc}",
        )


async def send_put_request(
    endpoint: str,
    data: Optional[Dict[str, Any]] = None,
    connector_name: str = DEFAULT_CONNECTOR_NAME,
) -> Dict[str, Any]:
    """
    Sends a PUT request to the N8N service.
    """
    logger.info("Sending PUT request to {}", endpoint)
    async with get_db_session() as session:
        attributes = await get_connector_info_from_db(connector_name, session)
    if attributes is None:
        logger.error("No N8N connector found in the database")
        return {"success": False, "message": "N8N connector not configured"}
    try:
        response = requests.put(
            f"{_build_base_url(attributes)}{_normalise_endpoint(endpoint)}",
            headers=_build_headers(attributes),
            json=data or {},
            timeout=DEFAULT_TIMEOUT,
            verify=False,
        )
        response.raise_for_status()
        logger.info("PUT {} returned status {}", endpoint, response.status_code)
        return {
            "data": response.json() if response.content else None,
            "success": True,
            "message": "Successfully updated data",
        }
    except HTTPException:
        raise
    except requests.HTTPError as exc:
        error_response = exc.response
        status_code = error_response.status_code if error_response else 500
        detail = error_response.text if error_response else str(exc)
        logger.error("Failed PUT request to {}: {}", endpoint, detail)
        raise HTTPException(status_code=status_code, detail=detail)
    except Exception as exc:
        logger.error("Failed PUT request to {} with error: {}", endpoint, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send PUT request to {endpoint} with error: {exc}",
        )


async def send_delete_request(
    endpoint: str,
    params: Optional[Dict[str, Any]] = None,
    connector_name: str = DEFAULT_CONNECTOR_NAME,
) -> Dict[str, Any]:
    """
    Sends a DELETE request to the N8N service.
    """
    logger.info("Sending DELETE request to {}", endpoint)
    async with get_db_session() as session:
        attributes = await get_connector_info_from_db(connector_name, session)
    if attributes is None:
        logger.error("No N8N connector found in the database")
        return {"success": False, "message": "N8N connector not configured"}
    try:
        response = requests.delete(
            f"{_build_base_url(attributes)}{_normalise_endpoint(endpoint)}",
            headers=_build_headers(attributes),
            params=params,
            timeout=DEFAULT_TIMEOUT,
            verify=False,
        )
        if response.status_code not in (200, 204):
            response.raise_for_status()
        logger.info("DELETE {} returned status {}", endpoint, response.status_code)
        return {
            "data": None,
            "success": True,
            "message": "Successfully deleted resource",
        }
    except HTTPException:
        raise
    except requests.HTTPError as exc:
        error_response = exc.response
        status_code = error_response.status_code if error_response else 500
        detail = error_response.text if error_response else str(exc)
        logger.error("Failed DELETE request to {}: {}", endpoint, detail)
        raise HTTPException(status_code=status_code, detail=detail)
    except Exception as exc:
        logger.error("Failed DELETE request to {} with error: {}", endpoint, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Failed to send DELETE request to {endpoint} with error: {exc}",
        )
