from app.services.orchestrator import run_diagnostic


def test_congestion_scenario():

    telemetry = [
        {
            "device_id": "CORE_SWITCH_01",

            "metrics": {
                "latency_ms": 280,
                "jitter_ms": 40,
                "packet_loss_pct": 3.5,
                "link_utilization_pct": 94,
                "cpu_percent": 68,
                "memory_percent": 72,
                "queue_drops": 160,
                "interface_errors": 2,
                "dns_ok": True,
                "dhcp_ok": True
            }
        }
    ]

    messages, report = run_diagnostic(
        "test-incident",
        telemetry
    )

    assert len(messages) == 5

    assert report["evidence"]

    assert report["confidence"] <= 1

    assert report["automation_performed"] is False


def test_normal_network_scenario():

    telemetry = [
        {
            "device_id": "SWITCH_02",

            "metrics": {
                "latency_ms": 20,
                "jitter_ms": 5,
                "packet_loss_pct": 0,
                "link_utilization_pct": 30,
                "cpu_percent": 25,
                "memory_percent": 40,
                "queue_drops": 0,
                "interface_errors": 0,
                "signal_dbm": -50,
                "dns_ok": True,
                "dhcp_ok": True
            }
        }
    ]

    messages, report = run_diagnostic(
        "normal-test",
        telemetry
    )

    assert report["severity"] == "low"

    assert report["probable_cause"] == "No significant fault detected"