
import multiprocessing as mp
from queue import Empty

from token_issuer import issue_token
from edge_controller import control_resource, RESOURCE_STATES


def tenant_workflow(tenant_id, token, workflow, request_queue, responses):
    """Run a tenant workflow in a separate process."""
    print(f"[{tenant_id}] Workflow started.", flush=True)

    for resource_id, action in workflow:
        request_queue.put((tenant_id, resource_id, action, token))
        approved = responses.get()
        status = "APPROVED" if approved else "DENIED"

        print(
            f"[{tenant_id}] {resource_id} -> {action}: {status}",
            flush=True,
        )

    print(f"[{tenant_id}] Workflow finished.", flush=True)


def main():
    print("\n=== MULTI-TENANT WORKFLOW DEMO ===")

    for resource_id in RESOURCE_STATES:
        RESOURCE_STATES[resource_id] = False

    token_a = issue_token("tenant_A", ["resource_A"])
    token_b = issue_token("tenant_B", ["resource_B"])

    request_queue = mp.Queue()
    response_queues = {
        "tenant_A": mp.Queue(),
        "tenant_B": mp.Queue(),
    }

    workflow_a = [
        ("resource_A", "ON"),
        ("resource_B", "ON"),
    ]

    workflow_b = [
        ("resource_B", "ON"),
        ("resource_A", "ON"),
    ]

    process_a = mp.Process(
        target=tenant_workflow,
        args=(
            "tenant_A", token_a, workflow_a,
            request_queue, response_queues["tenant_A"],
        ),
    )

    process_b = mp.Process(
        target=tenant_workflow,
        args=(
            "tenant_B", token_b, workflow_b,
            request_queue, response_queues["tenant_B"],
        ),
    )

    process_a.start()
    process_b.start()

    # Central controller: the only component that applies actions.
    pending = {}

    try:
        total_requests = len(workflow_a) + len(workflow_b)

        for _ in range(total_requests):
            tenant_id, resource_id, action, token = request_queue.get()

            print(
                f"[Controller] Received {tenant_id}: "
                f"{resource_id} -> {action}",
                flush=True,
            )

            approved = control_resource(token, resource_id, action)
            response_queues[tenant_id].put(approved)

    finally:
        process_a.join()
        process_b.join()

    print("\n--- FINAL RESOURCE STATES ---")
    for resource_id, state in sorted(RESOURCE_STATES.items()):
        print(f"{resource_id}: {'ON' if state else 'OFF'}")

    print("\n=== DEMONSTRATION COMPLETE ===")


if __name__ == "__main__":
    main()

