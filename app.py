import copy
import hashlib
import json
import os
import secrets
import threading

from flask import (
    Flask,
    jsonify,
    request
)

from planner import build_plan

from storage import (
    init_db,
    get_run,
    create_run,
    update_run,
    get_receipt,
    save_receipt
)

from trace_builder import (
    build_initial_trace,
    add_diagnostic_trace,
    new_id,
    make_traceparent,
    span
)


app = Flask(__name__)

init_db()

state_lock = threading.RLock()


PROFILE = "ga5-incident-agent/v2"


def canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )


def sha256_json(value):
    return hashlib.sha256(
        canonical_json(value).encode(
            "utf-8"
        )
    ).hexdigest()


def error_response(
    message,
    status
):
    return jsonify({
        "error": message
    }), status


def validate_request(body):

    if not isinstance(
        body,
        dict
    ):
        return False

    if body.get(
        "profile"
    ) != PROFILE:
        return False

    required = [
        "runId",
        "agentName",
        "publicMarker",
        "incident",
        "toolCatalog",
        "policy"
    ]

    for key in required:
        if key not in body:
            return False

    incident = body[
        "incident"
    ]

    required_incident = [
        "incidentId",
        "title",
        "service",
        "severity",
        "transcript",
        "allowedRootCauses"
    ]

    for key in required_incident:
        if key not in incident:
            return False

    if not isinstance(
        body["toolCatalog"],
        list
    ):
        return False

    if not isinstance(
        body["policy"],
        dict
    ):
        return False

    return True


def make_action_id():
    return (
        "act_" +
        secrets.token_hex(12)
    )


def make_call_id():
    return (
        "call_" +
        secrets.token_hex(12)
    )


def create_dispatch(
    diagnostic,
    run_id,
    public_marker,
    trace
):
    action_id = make_action_id()
    call_id = make_call_id()

    client_span_id = new_id(8)

    dispatch = {
        "actionId": action_id,
        "callId": call_id,
        "phase": "diagnostic",
        "toolName":
            diagnostic[
                "toolName"
            ],
        "arguments":
            diagnostic.get(
                "arguments",
                {}
            ),
        "evidence":
            diagnostic[
                "evidence"
            ],
        "attempt": 1,
        "traceparent":
            make_traceparent(
                trace[
                    "traceId"
                ],
                client_span_id
            )
    }

    dispatch["_runId"] = run_id
    dispatch[
        "_publicMarker"
    ] = public_marker

    # Remove internal values from
    # the externally visible dispatch.
    return dispatch


def public_dispatch(dispatch):
    result = copy.deepcopy(
        dispatch
    )

    result.pop(
        "_runId",
        None
    )

    result.pop(
        "_publicMarker",
        None
    )

    return result


def build_response_state(state):

    result = copy.deepcopy(
        state
    )

    result.pop(
        "internal",
        None
    )

    return result


@app.route(
    "/v2/incidents",
    methods=["POST"]
)
def create_incident():

    body = request.get_json(
        silent=True
    )

    if body is None:
        return error_response(
            "invalid_request",
            400
        )

    if not validate_request(
        body
    ):
        return error_response(
            "invalid_request",
            422
        )

    run_id = body[
        "runId"
    ]

    request_hash = sha256_json(
        body
    )

    with state_lock:

        existing = get_run(
            run_id
        )

        if existing:

            if (
                existing[
                    "request_hash"
                ]
                != request_hash
            ):
                return error_response(
                    "conflict",
                    409
                )

            return jsonify(
                build_response_state(
                    existing[
                        "state"
                    ]
                )
            )

        incident = body[
            "incident"
        ]

        # Sensitive fields are deliberately
        # never passed into build_plan().
        plan = build_plan(
            incident,
            body[
                "toolCatalog"
            ],
            body[
                "policy"
            ]
        )

        model_name = os.environ.get(
            "OPENAI_MODEL",
            "gpt-4o-mini"
        )

        trace = build_initial_trace(
            run_id,
            body[
                "publicMarker"
            ],
            body[
                "agentName"
            ],
            model_name
        )

        diagnosis = {
            "rootCause":
                plan[
                    "rootCause"
                ],
            "evidence":
                plan[
                    "evidence"
                ]
        }

        dispatches = []

        for diagnostic in plan[
            "diagnostics"
        ]:

            dispatch = create_dispatch(
                diagnostic,
                run_id,
                body[
                    "publicMarker"
                ],
                trace
            )

            # Create matching tool trace.
            add_diagnostic_trace(
                trace,
                dispatch,
                1
            )

            dispatches.append(
                public_dispatch(
                    dispatch
                )
            )

        state = {
            "runId": run_id,
            "status": "waiting",
            "diagnosis": diagnosis,
            "dispatches":
                dispatches,
            "approvals": [],
            "actionLog":
                dispatches,
            "receiptLog": [],
            "otlp": {
                "resourceSpans": [
                    {
                        "scopeSpans": [
                            {
                                "spans":
                                    trace[
                                        "spans"
                                    ]
                            }
                        ]
                    }
                ]
            },
            "internal": {
                "requestHash":
                    request_hash,
                "toolCatalog":
                    body[
                        "toolCatalog"
                    ],
                "policy":
                    body[
                        "policy"
                    ],
                "incident":
                    {
                        "incidentId":
                            incident[
                                "incidentId"
                            ],
                        "service":
                            incident[
                                "service"
                            ]
                    },
                "pending":
                    {
                        d[
                            "actionId"
                        ]: d
                        for d in dispatches
                    }
            }
        }

        create_run(
            run_id,
            request_hash,
            state
        )

        return jsonify(
            build_response_state(
                state
            )
        )


@app.route(
    "/v2/incidents/<run_id>",
    methods=["GET"]
)
def get_incident(
    run_id
):

    with state_lock:

        run = get_run(
            run_id
        )

        if not run:
            return error_response(
                "not_found",
                404
            )

        return jsonify(
            build_response_state(
                run[
                    "state"
                ]
            )
        )


@app.route(
    "/v2/incidents/<run_id>/receipts",
    methods=["POST"]
)
def receive_receipts(
    run_id
):

    body = request.get_json(
        silent=True
    )

    if not isinstance(
        body,
        dict
    ):
        return error_response(
            "invalid_request",
            400
        )

    receipt_hash = sha256_json(
        body
    )

    receipt_id = body.get(
        "receiptId"
    )

    if not receipt_id:
        return error_response(
            "invalid_request",
            422
        )

    with state_lock:

        run = get_run(
            run_id
        )

        if not run:
            return error_response(
                "not_found",
                404
            )

        existing_receipt = get_receipt(
            receipt_id
        )

        if existing_receipt:

            if (
                existing_receipt[
                    "request_hash"
                ]
                != receipt_hash
            ):
                return error_response(
                    "conflict",
                    409
                )

            return jsonify(
                build_response_state(
                    run[
                        "state"
                    ]
                )
            )

        state = run[
            "state"
        ]

        if state[
            "status"
        ] in (
            "completed",
            "failed"
        ):
            return jsonify(
                build_response_state(
                    state
                )
            )

        outcomes = body.get(
            "outcomes",
            []
        )

        approvals = body.get(
            "approvals",
            []
        )

        if outcomes:

            for outcome in outcomes:

                action_id = outcome.get(
                    "actionId"
                )

                pending = state[
                    "internal"
                ][
                    "pending"
                ].get(
                    action_id
                )

                if not pending:
                    return error_response(
                        "invalid_receipt",
                        409
                    )

                if (
                    pending[
                        "callId"
                    ]
                    != outcome.get(
                        "callId"
                    )
                ):
                    return error_response(
                        "invalid_receipt",
                        409
                    )

                if (
                    pending[
                        "attempt"
                    ]
                    != outcome.get(
                        "attempt"
                    )
                ):
                    return error_response(
                        "invalid_receipt",
                        409
                    )

                state[
                    "receiptLog"
                ].append({
                    "receiptId":
                        receipt_id,
                    "actionId":
                        action_id,
                    "callId":
                        outcome[
                            "callId"
                        ],
                    "attempt":
                        outcome[
                            "attempt"
                        ],
                    "status":
                        outcome.get(
                            "status",
                            0
                        ),
                    "resultClass":
                        outcome.get(
                            "resultClass"
                        ),
                    "nonce":
                        outcome.get(
                            "nonce"
                        )
                })

                state[
                    "internal"
                ][
                    "pending"
                ].pop(
                    action_id,
                    None
                )

            save_receipt(
                receipt_id,
                run_id,
                receipt_hash,
                body
            )

            # If all diagnostic calls succeeded,
            # select an effect.
            if not state[
                "internal"
            ][
                "pending"
            ]:

                policy = state[
                    "internal"
                ][
                    "policy"
                ]

                effect_tools = policy.get(
                    "effectTools",
                    []
                )

                approval_required = policy.get(
                    "approvalRequiredFor",
                    []
                )

                if effect_tools:

                    effect_tool = effect_tools[
                        0
                    ]

                    if (
                        effect_tool
                        in approval_required
                    ):
                        approval_id = (
                            "approval_" +
                            secrets.token_hex(
                                12
                            )
                        )

                        action_id = (
                            "effect_" +
                            secrets.token_hex(
                                12
                            )
                        )

                        arguments = {}

                        arguments_digest = (
                            sha256_json(
                                arguments
                            )
                        )

                        state[
                            "approvals"
                        ] = [{
                            "approvalId":
                                approval_id,
                            "actionId":
                                action_id,
                            "toolName":
                                effect_tool,
                            "argumentsDigest":
                                arguments_digest
                        }]

                        state[
                            "internal"
                        ][
                            "pendingApproval"
                        ] = {
                            "approvalId":
                                approval_id,
                            "actionId":
                                action_id,
                            "toolName":
                                effect_tool,
                            "arguments":
                                arguments
                        }

                    else:

                        state[
                            "status"
                        ] = "completed"

                        state[
                            "chosenEffect"
                        ] = effect_tool

                else:

                    state[
                        "status"
                    ] = "completed"

        if approvals:

            pending_approval = state[
                "internal"
            ].get(
                "pendingApproval"
            )

            if not pending_approval:
                return error_response(
                    "invalid_approval",
                    409
                )

            approval = approvals[
                0
            ]

            if (
                approval[
                    "approvalId"
                ]
                != pending_approval[
                    "approvalId"
                ]
            ):
                return error_response(
                    "invalid_approval",
                    409
                )

            if (
                approval[
                    "decision"
                ]
                != "approved"
            ):
                state[
                    "status"
                ] = "failed"

            else:

                state[
                    "receiptLog"
                ].append({
                    "receiptId":
                        receipt_id,
                    "approvalId":
                        approval[
                            "approvalId"
                        ],
                    "decision":
                        approval[
                            "decision"
                        ],
                    "nonce":
                        approval[
                            "nonce"
                        ]
                })

                tool_name = (
                    pending_approval[
                        "toolName"
                    ]
                )

                action_id = (
                    pending_approval[
                        "actionId"
                    ]
                )

                dispatch = {
                    "actionId":
                        action_id,
                    "callId":
                        action_id,
                    "phase":
                        "effect",
                    "toolName":
                        tool_name,
                    "arguments":
                        pending_approval[
                            "arguments"
                        ],
                    "evidence":
                        state[
                            "diagnosis"
                        ][
                            "evidence"
                        ],
                    "attempt":
                        1,
                    "approvalId":
                        pending_approval[
                            "approvalId"
                        ],
                    "approvalNonce":
                        approval[
                            "nonce"
                        ]
                }

                state[
                    "dispatches"
                ] = [
                    dispatch
                ]

                state[
                    "actionLog"
                ].append(
                    dispatch
                )

                state[
                    "internal"
                ][
                    "pending"
                ][
                    action_id
                ] = dispatch

                state[
                    "internal"
                ].pop(
                    "pendingApproval",
                    None
                )

                state[
                    "approvals"
                ] = []

                state[
                    "chosenEffect"
                ] = tool_name

        # Terminal state only after
        # actual effect receipt.
        if (
            state[
                "status"
            ] == "waiting"
            and not state[
                "internal"
            ][
                "pending"
            ]
            and not state[
                "approvals"
            ]
        ):
            state[
                "status"
            ] = "completed"

        update_run(
            run_id,
            state
        )

        return jsonify(
            build_response_state(
                state
            )
        )


@app.errorhandler(
    404
)
def not_found(error):
    return error_response(
        "not_found",
        404
    )


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        )
    )
