import asyncio
import os

from typing import List

from fastapi import APIRouter
from fastapi import Depends
from fastapi import Header
from fastapi import HTTPException
from fastapi import Query
from fastapi import Security
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.active_response.routes.graylog import verify_graylog_header
from app.active_response.schema.graylog import GraylogThresholdEventNotification
from app.auth.utils import AuthHandler
from app.db.db_session import get_db
from app.incidents.schema.alert_collection import AlertsPayload
from app.connectors.graylog.utils.universal import send_post_request
from app.connectors.wazuh_indexer.schema.alerts import AlertsSearchBody
from app.connectors.wazuh_indexer.schema.alerts import HostAlertsSearchBody
from app.connectors.wazuh_indexer.services.alerts import collect_alerts_generic
from app.agents.vulnerabilities.schema.vulnerabilities import AgentVulnerabilityOut
from app.agents.vulnerabilities.services.vulnerabilities import get_vulnerabilities_by_agent
from app.incidents.schema.incident_alert import AlertCorrelationAgent
from app.incidents.schema.incident_alert import AlertCorrelationAlert
from app.incidents.schema.incident_alert import AlertCorrelationCase
from app.incidents.schema.incident_alert import AlertCorrelationResponse
from app.incidents.schema.incident_alert import AlertCorrelationVulnerability
from app.incidents.schema.incident_alert import AlertDetailsResponse
from app.incidents.schema.incident_alert import AlertTimelineResponse
from app.incidents.schema.incident_alert import AutoCreateAlertResponse
from app.incidents.schema.incident_alert import CreateAlertRequest
from app.incidents.schema.incident_alert import CreateAlertRequestRoute
from app.incidents.schema.incident_alert import CreateAlertResponse
from app.incidents.schema.incident_alert import CreatedAlertPayload
from app.incidents.schema.incident_alert import IndexNamesResponse
from app.db.universal_models import Agents
from app.incidents.schema.velo_sigma import VelociraptorSigmaAlert
from app.incidents.schema.velo_sigma import VelociraptorSigmaAlertResponse
from app.incidents.schema.velo_sigma import VeloSigmaExclusionCreate
from app.incidents.schema.velo_sigma import VeloSigmaExclusionListResponse
from app.incidents.schema.velo_sigma import VeloSigmaExclusionUpdate
from app.incidents.schema.velo_sigma import VeloSigmaExlcusionRouteResponse
from app.incidents.services.alert_collection import add_copilot_alert_id
from app.incidents.services.alert_collection import get_alerts_not_created_in_copilot
from app.incidents.services.alert_collection import get_graylog_event_indices
from app.incidents.services.alert_collection import get_original_alert_id
from app.incidents.services.alert_collection import get_original_alert_index_name
from app.incidents.services.incident_alert import create_alert
from app.incidents.services.incident_alert import create_alert_full
from app.incidents.services.incident_alert import retrieve_agent_details_from_db
from app.incidents.services.incident_alert import get_single_alert_details
from app.incidents.services.incident_alert import retrieve_alert_timeline
from app.incidents.services.db_operations import list_cases_by_asset_name
from app.incidents.services.velo_sigma import VeloSigmaExclusionService
from app.incidents.services.velo_sigma import create_velo_sigma_alert

incidents_alerts_router = APIRouter()


# Function to validate the Velociraptor header
async def verify_velociraptor_header(velociraptor: str = Header(None)):
    """Verify that the request has the correct Velociraptor header."""
    # Get the header value from environment variable or use "ab73de7a-6f61-4dde-87cd-3af5175a7281" as default
    expected_header = os.getenv("VELOCIRAPTOR_API_HEADER_VALUE", "ab73de7a-6f61-4dde-87cd-3af5175a7281")

    if velociraptor != expected_header:
        logger.error("Invalid or missing Velociraptor header")
        raise HTTPException(status_code=403, detail="Invalid or missing Velociraptor header")
    return velociraptor


@incidents_alerts_router.get(
    "/index/names",
    response_model=IndexNamesResponse,
    description="Get the Graylog event indices",
)
async def get_index_names_route() -> IndexNamesResponse:
    """
    Get the Graylog event indices. Get the Graylog event indices for the Graylog events.

    Returns:
        List[str]: The list of Graylog event indices.
    """
    return await get_graylog_event_indices()


@incidents_alerts_router.get(
    "/alerts/not-created",
    description="Get alerts not created in CoPilot",
)
async def get_alerts_not_created_route() -> AlertsPayload:
    """
    Get alerts not created in CoPilot. Get all the results from the list of indices, where `copilot_alert_id` does not exist.

    Returns:
        List[AlertPayloadItem]: The list of alerts that have not been created in CoPilot.
    """
    return await get_alerts_not_created_in_copilot()


@incidents_alerts_router.post(
    "/alert/details",
    description="Get the details of a single alert",
)
async def get_single_alert_details_route(
    create_alert_request: CreateAlertRequestRoute,
) -> AlertDetailsResponse:
    """
    Get the details of a single alert. Get the details of a single alert based on the alert id.
    Takes the alert id and the index name as input.

    Args:
        create_alert_request (CreateAlertRequestRoute): The request object containing the details of the alert to be created.

    Returns:
        class AlertDetailsResponse(BaseModel): The response object containing the details of the alert.
    """
    return AlertDetailsResponse(
        success=True,
        message="Alert details retrieved",
        alert_details=await get_single_alert_details(
            CreateAlertRequest(index_name=create_alert_request.index_name, alert_id=create_alert_request.index_id),
        ),
    )


@incidents_alerts_router.post(
    "/alert/timeline",
    description="Get the timeline of an alert",
)
async def get_alert_timeline_route(
    alert: CreateAlertRequestRoute,
    session: AsyncSession = Depends(get_db),
) -> AlertTimelineResponse:
    """
    Get the timeline of an alert. This route obtains the process_id from the alert details if it exists
    and queries the Indexer for all events with the same process_id and hostname within a 24 hour period.

    Args:
        create_alert_request (CreateAlertRequestRoute): The request object containing the details of the alert to be created.


    Returns:
        class AlertTimelineResponse(BaseModel): The response object containing the details of the alert.
    """
    # await retrieve_alert_timeline(alert, session)
    return AlertTimelineResponse(
        success=True,
        message="Alert timeline retrieved",
        alert_timeline=await retrieve_alert_timeline(alert, session),
    )


@incidents_alerts_router.post(
    "/alert/correlation",
    response_model=AlertCorrelationResponse,
    description="Get correlated context for an alert",
    dependencies=[Security(AuthHandler().require_any_scope("admin", "analyst"))],
)
async def get_alert_correlation_route(
    alert: CreateAlertRequestRoute,
    session: AsyncSession = Depends(get_db),
) -> AlertCorrelationResponse:
    try:
        correlation_payload = await _build_alert_correlation(alert, session)
        return AlertCorrelationResponse(
            success=True,
            message="Alert correlation data retrieved successfully",
            **correlation_payload,
        )
    except HTTPException as exc:
        raise exc
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(f"Failed to gather alert correlation: {exc}")
        raise HTTPException(status_code=500, detail=f"Failed to gather alert correlation: {exc}")


@incidents_alerts_router.post(
    "/create/manual",
    response_model=CreateAlertResponse,
    description="Manually create an incident alert in CoPilot",
    dependencies=[Security(AuthHandler().require_any_scope("admin", "analyst"))],
)
async def create_alert_manual_route(
    create_alert_request: CreateAlertRequest,
    session: AsyncSession = Depends(get_db),
) -> CreateAlertResponse:
    """
    Create an incident alert in CoPilot. Manually create an incident alert within CoPilot.
    Used via the Alerts, for manual incident alert creation.

    Args:
        create_alert_request (CreateAlertRequest): The request object containing the details of the alert to be created.
        session (AsyncSession, optional): The database session. Defaults to Depends(get_session).

    Returns:
        CreateAlertResponse: The response object containing the result of the alert creation.
    """
    logger.info(f"Creating alert {create_alert_request.alert_id} in CoPilot")
    return CreateAlertResponse(success=True, message="Alert created in CoPilot", alert_id=await create_alert(create_alert_request, session))


@incidents_alerts_router.post(
    "/create/auto",
    response_model=CreateAlertResponse,
    description="Is invoked by the scheduler to create an incident alert in CoPilot",
)
async def create_alert_auto_route(
    session: AsyncSession = Depends(get_db),
) -> AutoCreateAlertResponse:
    """
    Create an incident alert in CoPilot. Automatically create an incident alert within CoPilot.
    This queries the `gl-events-*` indices for alerts that have not been created in CoPilot.
    It is important to note that Graylog must be configured for the alerts.

    Args:
        create_alert_request (CreateAlertRequest): The request object containing the details of the alert to be created.
        session (AsyncSession, optional): The database session. Defaults to Depends(get_session).

    Returns:
        CreateAlertResponse: The response object containing the result of the alert creation.
    """
    alerts = await get_alerts_not_created_in_copilot()
    logger.info(f"Alerts to create in CoPilot: {alerts}")
    if len(alerts.alerts) == 0:
        return AutoCreateAlertResponse(success=False, message="No alerts to create in CoPilot")

    created_alerts_count = 0

    for alert in alerts.alerts:
        try:
            logger.info(f"Creating alert {alert} in CoPilot")
            create_alert_request = CreateAlertRequest(
                index_name=await get_original_alert_index_name(origin_context=alert.source.origin_context),
                alert_id=await get_original_alert_id(alert.source.origin_context),
            )
            logger.info(f"Creating alert {create_alert_request.alert_id} in CoPilot")
            alert_id = await create_alert(create_alert_request, session)
            # ! ADD THE COPILOT ALERT ID TO GRAYLOG EVENT INDEX # !
            await add_copilot_alert_id(index_data=CreateAlertRequest(index_name=alert.index, alert_id=alert.id), alert_id=alert_id)
            created_alerts_count += 1
        except Exception as e:
            logger.error(f"Failed to create alert {alert} in CoPilot: {e}")


@incidents_alerts_router.post(
    "/create/threshold",
    response_model=CreateAlertResponse,
    description="Creates an incident alert in CoPilot for a Graylog configured threshold alert",
    dependencies=[Depends(verify_graylog_header)],
)
async def invoke_alert_threshold_graylog_route(
    request: GraylogThresholdEventNotification,
    session: AsyncSession = Depends(get_db),
) -> CreateAlertResponse:
    """
    This route accepts an HTTP Post from Graylog for any threshold alerts which needs a dedicated route
    because there is no individual alert with an _id that we can use to grab from the
    wazuh-indexer.
    REQUIRED FILEDS:
    1. CUSTOMER_CODE: str - the customer code
    2. SOURCE: str - the source of the alert
    3. ALERT_DESCRIPTION: str - the description of the alert
    4. ASSET_NAME: str - the name of the asset

    # ! IMPORTANT: DO NOT ADD THE "COPILOT_ALERT_ID": "NONE" AS A CUSTOM FIELD WHEN CREATING THE ALERT IN GRAYLOG # !
        # ! THIS WILL BREAK THE AUTO-ALERT CREATION FUNCTIONALITY # !

    # ! Make sure the Graylog Notification is just the standard HTTP Notification Type and not the Custom HTTP Notification Type !

    Args:
        request (InvokeActiveResponseRequest): The request object containing the command, custom, arguments, and alert.

    Returns:
        CreateAlertResponse: The response object containing the result of the alert creation.
    """
    logger.info("Invoking alert threshold Graylog...")
    logger.info(f"Timestamp: {request.event.timestamp}")
    alert_id = await create_alert_full(
        alert_payload=CreatedAlertPayload(
            alert_context_payload=request.event.fields.dict(),
            asset_payload=request.event.fields.ASSET_NAME,
            timefield_payload=str(request.event.timestamp),
            alert_title_payload=request.event.message,
            source=request.event.fields.SOURCE,
            index_name="not_applicable",
            index_id="not_applicable",
        ),
        customer_code=request.event.fields.CUSTOMER_CODE,
        session=session,
        threshold_alert=True,
    )
    return CreateAlertResponse(success=True, message="Alert threshold Graylog invoked successfully", alert_id=alert_id)


@incidents_alerts_router.post(
    "/create/velo-sigma",
    response_model=VelociraptorSigmaAlertResponse,
    description="Creates an incident alert in CoPilot for a Velociraptor Sigma alert",
    dependencies=[Depends(verify_velociraptor_header)],
)
async def process_sigma_alert(alert: VelociraptorSigmaAlert, session: AsyncSession = Depends(get_db)) -> VelociraptorSigmaAlertResponse:
    """
    This route receives a Velociraptor Sigma alert. You must have defined the Windows.Hayabusa.Monitoring
    client Event defined which will search for the Sigma alert in the Velociraptor client.
    When a Sigma alert is found, Velociraptor will us the `CoPilot.Events.Upload` to send a POST
    request to this endpoint with the alert data.

    An issue is that we want to fetch the wazuh event that is related to the Sigma alert so that we can
    create the alert within CoPilot accordingly. To do this we extract the `computer` as the `agent_name`
    and the `EventRecordID` as the `data_win_system_eventRecordID` and then query the Wazuh Indexer
    to fetch this sepcific event with a timeframe of 1 hour.

    Then we progress through the CoPilot Alert Creation process as normal.
    """
    logger.info(f"Processing Velociraptor Sigma alert: {alert}")
    return await create_velo_sigma_alert(alert, session)


@incidents_alerts_router.post(
    "/create/velo-sigma/exclusion",
    response_model=VeloSigmaExlcusionRouteResponse,
    summary="Create a new Velociraptor Sigma exclusion rule",
)
async def create_exclusion(
    exclusion: VeloSigmaExclusionCreate,
    current_user: str = Depends(AuthHandler().return_username_for_logging),
    db: AsyncSession = Depends(get_db),
):
    """Create a new exclusion rule for Velociraptor Sigma alerts."""
    # Set the created_by field to the current user
    logger.info(f"Current user: {current_user}")

    # Take only needed fields from exclusion, excluding created_by
    exclusion_dict = exclusion.dict(exclude={"created_by"})
    # Create a new exclusion with the current user
    updated_exclusion = VeloSigmaExclusionCreate(**exclusion_dict, created_by=current_user)

    # Log the exclusion data for debugging
    logger.info(f"Exclusion data: {updated_exclusion.dict()}")

    service = VeloSigmaExclusionService(db)
    # return await service.create_exclusion(updated_exclusion)
    return VeloSigmaExlcusionRouteResponse(
        success=True,
        message="Exclusion rule created successfully",
        exclusion_response=await service.create_exclusion(updated_exclusion),
    )


@incidents_alerts_router.get(
    "/create/velo-sigma/exclusion/{exclusion_id}",
    response_model=VeloSigmaExlcusionRouteResponse,
    summary="Get an exclusion rule by ID",
)
async def get_exclusion(
    exclusion_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(AuthHandler().get_current_user),
):
    """Retrieve details of a specific exclusion rule."""
    service = VeloSigmaExclusionService(db)
    exclusion = await service.get_exclusion(exclusion_id)

    if not exclusion:
        raise HTTPException(status_code=404, detail="Exclusion rule not found")

    return VeloSigmaExlcusionRouteResponse(
        success=True,
        message="Exclusion rule retrieved successfully",
        exclusion_response=exclusion,
    )


@incidents_alerts_router.get(
    "/create/velo-sigma/exclusion",
    response_model=VeloSigmaExclusionListResponse,
    summary="List all exclusion rules",
)
async def list_exclusions(
    skip: int = Query(0, description="Number of items to skip for pagination"),
    limit: int = Query(100, description="Maximum number of items to return"),
    enabled_only: bool = Query(False, description="Only return enabled exclusions"),
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(AuthHandler().get_current_user),
):
    """List all exclusion rules with pagination."""
    service = VeloSigmaExclusionService(db)

    # Get exclusions and total count
    exclusions, total_count = await service.list_exclusions_with_count(skip=skip, limit=limit, enabled_only=enabled_only)

    return VeloSigmaExclusionListResponse(
        success=True,
        message="Exclusion rules retrieved successfully",
        exclusions=exclusions,
        pagination={"total": total_count, "skip": skip, "limit": limit},
    )


@incidents_alerts_router.patch(
    "/create/velo-sigma/exclusion/{exclusion_id}",
    response_model=VeloSigmaExlcusionRouteResponse,
    summary="Update an exclusion rule",
)
async def update_exclusion(
    exclusion_id: int,
    exclusion: VeloSigmaExclusionUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(AuthHandler().get_current_user),
):
    """Update an existing exclusion rule."""
    service = VeloSigmaExclusionService(db)
    updated = await service.update_exclusion(exclusion_id, exclusion.dict(exclude_unset=True))

    if not updated:
        raise HTTPException(status_code=404, detail="Exclusion rule not found")

    # return updated
    return VeloSigmaExlcusionRouteResponse(
        success=True,
        message="Exclusion rule updated successfully",
        exclusion_response=updated,
    )


@incidents_alerts_router.delete("/create/velo-sigma/exclusion/{exclusion_id}", summary="Delete an exclusion rule")
async def delete_exclusion(
    exclusion_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(AuthHandler().get_current_user),
):
    """Delete an exclusion rule."""
    service = VeloSigmaExclusionService(db)
    deleted = await service.delete_exclusion(exclusion_id)

    if not deleted:
        raise HTTPException(status_code=404, detail="Exclusion rule not found")

    return {"message": "Exclusion rule deleted successfully", "success": True}


@incidents_alerts_router.post(
    "/velo-sigma/exclusion/{exclusion_id}/toggle",
    response_model=VeloSigmaExlcusionRouteResponse,
    summary="Toggle an exclusion rule's enabled status",
)
async def toggle_exclusion(
    exclusion_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(AuthHandler().get_current_user),
):
    """Enable or disable an exclusion rule."""
    service = VeloSigmaExclusionService(db)
    exclusion = await service.get_exclusion(exclusion_id)

    if not exclusion:
        raise HTTPException(status_code=404, detail="Exclusion rule not found")

    # Toggle the enabled status
    updated = await service.update_exclusion(exclusion_id, {"enabled": not exclusion.enabled})
    # return updated
    return VeloSigmaExlcusionRouteResponse(
        success=True,
        message="Exclusion rule toggled successfully",
        exclusion_response=updated,
    )


async def _build_alert_correlation(
    alert: CreateAlertRequestRoute,
    session: AsyncSession,
) -> dict:
    correlation_agent = None
    vulnerabilities: List[AlertCorrelationVulnerability] = []
    recent_alerts: List[AlertCorrelationAlert] = []
    cases: List[AlertCorrelationCase] = []

    alert_details = await get_single_alert_details(
        CreateAlertRequest(index_name=alert.index_name, alert_id=alert.index_id),
    )

    alert_source = alert_details._source
    hostname = getattr(alert_source, "agent_name", None) or getattr(alert_source, "hostname", None)

    agent_record = None
    if hostname:
        agent_record = await retrieve_agent_details_from_db(hostname, session)

    if not agent_record and alert.agent_id:
        agent_result = await session.execute(select(Agents).filter(Agents.agent_id == alert.agent_id))
        agent_record = agent_result.scalars().first()

    if agent_record:
        correlation_agent = AlertCorrelationAgent(
            agent_id=agent_record.agent_id,
            hostname=agent_record.hostname,
            ip_address=agent_record.ip_address,
            os=agent_record.os,
            label=agent_record.label,
            wazuh_agent_status=agent_record.wazuh_agent_status,
            wazuh_last_seen=agent_record.wazuh_last_seen,
            velociraptor_id=agent_record.velociraptor_id,
            velociraptor_last_seen=agent_record.velociraptor_last_seen,
            customer_code=agent_record.customer_code,
            critical_asset=agent_record.critical_asset,
        )

        vuln_response = await get_vulnerabilities_by_agent(session, agent_record.agent_id)
        if vuln_response.success and vuln_response.vulnerabilities:
            severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

            def _vuln_sort_key(vuln: AgentVulnerabilityOut):
                timestamp = vuln.discovered_at.timestamp() if vuln.discovered_at else 0
                return severity_order.get(vuln.severity, 99), -timestamp

            sorted_vulns = sorted(vuln_response.vulnerabilities, key=_vuln_sort_key)
            for vuln in sorted_vulns[:5]:
                vulnerabilities.append(
                    AlertCorrelationVulnerability(
                        id=vuln.id,
                        cve_id=vuln.cve_id,
                        severity=vuln.severity,
                        title=vuln.title,
                        status=vuln.status,
                        discovered_at=vuln.discovered_at,
                        epss_score=vuln.epss_score,
                        epss_percentile=vuln.epss_percentile,
                    ),
                )

    host_identifier = hostname or (agent_record.hostname if agent_record else None)
    if host_identifier:
        # Prefer direct Graylog search for broader signal coverage
        graylog_alerts = await _collect_graylog_signals(host_identifier)
        if graylog_alerts:
            recent_alerts.extend(graylog_alerts)
        else:
            search_body = HostAlertsSearchBody(agent_name=host_identifier, size=10)
            try:
                alerts_response = await collect_alerts_generic(alert.index_name, search_body, is_host_specific=True)
                if alerts_response.success and alerts_response.alerts:
                    for alert_item in alerts_response.alerts[:5]:
                        source = alert_item.get("_source", {})
                        timestamp = source.get("timestamp") or source.get("@timestamp")
                        recent_alerts.append(
                            AlertCorrelationAlert(
                                index=alert_item.get("_index"),
                                id=alert_item.get("_id"),
                                timestamp=timestamp,
                                rule_description=source.get("rule_description") or source.get("rule_name"),
                                syslog_level=source.get("syslog_level"),
                                message=source.get("message") or source.get("full_log"),
                            ),
                        )
            except HTTPException as exc:
                logger.warning(f"Failed to collect recent alerts for host {host_identifier}: {exc.detail}")

        try:
            case_results = await list_cases_by_asset_name(host_identifier, session)
            if case_results:
                for case in case_results:
                    cases.append(
                        AlertCorrelationCase(
                            id=case.id,
                            case_name=case.case_name,
                            status=case.case_status,
                            created_at=case.case_creation_time,
                        ),
                    )
                cases.sort(
                    key=lambda c: c.created_at.timestamp() if c.created_at else 0,
                    reverse=True,
                )
                cases = cases[:5]
        except HTTPException as exc:
            logger.warning(f"Failed to collect cases for host {host_identifier}: {exc.detail}")

    return {
        "agent": correlation_agent,
        "vulnerabilities": vulnerabilities,
        "recent_alerts": recent_alerts,
        "cases": cases,
    }


async def _collect_graylog_signals(host_identifier: str, *, timerange_minutes: int = 1440, limit: int = 20) -> List[AlertCorrelationAlert]:
    """Query Graylog for recent events related to the host.

    Args:
        host_identifier: hostname/agent identifier to search for.
        timerange_minutes: relative timeframe to search (default 24h).
        limit: maximum number of events to retrieve.

    Returns:
        List[AlertCorrelationAlert]: formatted alert entries (up to 5). Empty if none available.
    """

    query_terms = [
        f"hostname:{host_identifier}",
        f"agent_name:{host_identifier}",
        f"agent_hostname:{host_identifier}",
    ]
    payload = {
        "query": " OR ".join(query_terms),
        "range": timerange_minutes,
        "limit": limit,
        "sort": [
            {
                "field": "timestamp",
                "order": "desc",
            },
        ],
    }

    try:
        response = await send_post_request("/api/search/universal/relative", data=payload)
    except HTTPException as exc:
        logger.warning(f"Graylog correlation search failed for {host_identifier}: {exc.detail}")
        return []
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(f"Unexpected error querying Graylog for {host_identifier}: {exc}")
        return []

    messages = response.get("data", {}).get("messages", []) if response else []
    if not messages:
        return []

    alerts: List[AlertCorrelationAlert] = []
    for message_wrapper in messages[:limit]:
        message = message_wrapper.get("message", {})
        timestamp = message.get("timestamp")
        rule_description = message.get("rule_description") or message.get("description")
        syslog_level = message.get("syslog_level") or message.get("level")
        alerts.append(
            AlertCorrelationAlert(
                index=message_wrapper.get("index"),
                id=message.get("_id") or message_wrapper.get("id"),
                timestamp=timestamp,
                rule_description=rule_description,
                syslog_level=str(syslog_level) if syslog_level is not None else None,
                message=message.get("message"),
            ),
        )

    # Deduplicate and limit to 5 entries for UI readability
    unique_alerts = []
    seen_ids = set()
    for alert in alerts:
        primary_id = (alert.id, alert.timestamp, alert.message)
        if primary_id in seen_ids:
            continue
        seen_ids.add(primary_id)
        unique_alerts.append(alert)
        if len(unique_alerts) >= 5:
            break

    return unique_alerts
