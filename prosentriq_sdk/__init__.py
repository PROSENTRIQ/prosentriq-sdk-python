"""Prosentriq Sensor SDK (blueprint 3.1: "Publish the schema and a small Sensor SDK").

    from prosentriq_sdk import Client, events

    client = Client.enroll("https://api.prosentriq.com", enrollment_key, hostname="appliance-1",
                           sensor_type="sdk", os="linux")
    client.send([events.auth("185.220.101.4", user="admin", success=False, host_id="appliance-1")])
    for directive in client.heartbeat()["directives"]:
        ...  # apply, then acknowledge on the next heartbeat

The wire contract is the canonical event schema published at
GET /v2/public/schema (schema/prosentriq-event.schema.json in the repo).
"""
from prosentriq_sdk import events
from prosentriq_sdk.client import ApiError, Client, resolve_chain, verify_feed, verify_signature

__all__ = ["Client", "ApiError", "events", "resolve_chain", "verify_feed", "verify_signature"]
__version__ = "2.0.0"
