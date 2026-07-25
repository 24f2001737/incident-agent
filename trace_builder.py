import secrets
import time


def new_id(bytes_count=16):
    return secrets.token_hex(bytes_count)


def make_traceparent(
    trace_id,
    span_id
):
    return (
        f"00-{trace_id}-"
        f"{span_id}-01"
    )


def span(
    name,
    kind,
    trace_id,
    span_id,
    parent_span_id,
    attributes,
    status_code=0,
    status_message=None,
    links=None
):
    result = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "startTimeUnixNano":
            str(time.time_ns()),
        "endTimeUnixNano":
            str(time.time_ns()),
        "attributes": [
            {
                "key": key,
                "value": {
                    "stringValue": value
                }
            }
            for key, value in attributes.items()
        ],
        "status": {
            "code": status_code
        }
    }

    if parent_span_id:
        result["parentSpanId"] = parent_span_id

    if status_message:
        result["status"]["message"] = (
            status_message
        )

    if links:
        result["links"] = links

    return result


def build_initial_trace(
    run_id,
    public_marker,
    agent_name,
    model_name
):
    trace_id = new_id(16)

    server_span_id = new_id(8)

    agent_span_id = new_id(8)

    model_span_id = new_id(8)

    common = {
        "ga5.run.id": run_id,
        "ga5.public.marker": public_marker
    }

    server = span(
        "POST /v2/incidents",
        2,
        trace_id,
        server_span_id,
        None,
        common
    )

    agent = span(
        "invoke_agent incident-response",
        1,
        trace_id,
        agent_span_id,
        server_span_id,
        common
    )

    model_attributes = {
        **common,
        "gen_ai.operation.name": "chat",
        "gen_ai.request.model": model_name
    }

    model = span(
        "chat incident-plan",
        3,
        trace_id,
        model_span_id,
        agent_span_id,
        model_attributes
    )

    return {
        "traceId": trace_id,
        "serverSpanId": server_span_id,
        "agentSpanId": agent_span_id,
        "spans": [
            server,
            agent,
            model
        ]
    }


def add_diagnostic_trace(
    trace,
    action,
    attempt,
    receipt=None,
    error_type=None
):
    trace_id = trace["traceId"]

    agent_span_id = trace[
        "agentSpanId"
    ]

    action_id = action[
        "actionId"
    ]

    tool_name = action[
        "toolName"
    ]

    logical_span_id = new_id(8)

    client_span_id = new_id(8)

    common = {
        "ga5.run.id":
            action.get("_runId", ""),
        "ga5.public.marker":
            action.get("_publicMarker", "")
    }

    logical_attrs = {
        **common,
        "ga5.action.id":
            action_id,
        "gen_ai.tool.name":
            tool_name,
        "gen_ai.tool.call.id":
            action["callId"],
        "gen_ai.operation.name":
            "execute_tool"
    }

    logical = span(
        f"execute_tool {tool_name}",
        1,
        trace_id,
        logical_span_id,
        agent_span_id,
        logical_attrs
    )

    client_attrs = {
        **common,
        "ga5.action.id":
            action_id,
        "ga5.attempt":
            str(attempt),
        "http.request.method":
            "POST",
        "http.request.resend_count":
            str(attempt - 1)
    }

    if receipt:
        client_attrs[
            "ga5.receipt.id"
        ] = receipt.get(
            "receiptId",
            ""
        )

        client_attrs[
            "ga5.receipt.nonce"
        ] = receipt.get(
            "nonce",
            ""
        )

        client_attrs[
            "http.response.status_code"
        ] = str(
            receipt.get(
                "status",
                0
            )
        )

    if error_type:
        client_attrs[
            "error.type"
        ] = error_type

    status_code = 0

    if receipt:
        if receipt.get(
            "status"
        ) >= 400:
            status_code = 2

    if error_type:
        status_code = 2

    client = span(
        f"POST tool/{tool_name}",
        3,
        trace_id,
        client_span_id,
        logical_span_id,
        client_attrs,
        status_code=status_code
    )

    trace["spans"].extend([
        logical,
        client
    ])

    return client_span_id
