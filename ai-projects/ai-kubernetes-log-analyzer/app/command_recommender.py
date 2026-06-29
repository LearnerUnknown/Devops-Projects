"""Generate kubectl command recommendations based on detected Kubernetes issues."""


COMMAND_MAP = {
    "CrashLoopBackOff": [
        {
            "command": "kubectl get pods -n <namespace>",
            "purpose": "List all pods and their current status",
        },
        {
            "command": "kubectl describe pod <pod-name> -n <namespace>",
            "purpose": "Get detailed pod information including events and conditions",
        },
        {
            "command": "kubectl logs <pod-name> -n <namespace> --previous",
            "purpose": "View logs from the previous crashed container instance",
        },
        {
            "command": "kubectl get events -n <namespace> --sort-by=.lastTimestamp",
            "purpose": "View recent events sorted by time to identify failure sequence",
        },
        {
            "command": "kubectl describe deployment <deployment-name> -n <namespace>",
            "purpose": "Check deployment spec for misconfigured env vars, commands, or images",
        },
    ],
    "ImagePullBackOff": [
        {
            "command": "kubectl describe pod <pod-name> -n <namespace>",
            "purpose": "Check image pull error details in pod events",
        },
        {
            "command": "kubectl get secret -n <namespace>",
            "purpose": "List secrets to verify imagePullSecret exists",
        },
        {
            "command": "kubectl get serviceaccount -n <namespace>",
            "purpose": "Check if service account has imagePullSecrets attached",
        },
        {
            "command": (
                "kubectl patch serviceaccount default "
                "-p '{\"imagePullSecrets\":[{\"name\":\"<secret-name>\"}]}' "
                "-n <namespace>"
            ),
            "purpose": "Attach imagePullSecret to the default service account",
        },
        {
            "command": "az acr login --name <acr-name>",
            "purpose": "Authenticate to Azure Container Registry",
        },
    ],
    "OOMKilled": [
        {
            "command": "kubectl describe pod <pod-name> -n <namespace>",
            "purpose": "View OOMKilled status and container resource limits",
        },
        {
            "command": "kubectl top pod <pod-name> -n <namespace>",
            "purpose": "Check current memory and CPU usage of the pod",
        },
        {
            "command": "kubectl top nodes",
            "purpose": "Check overall node resource utilization",
        },
        {
            "command": "kubectl get deployment <deployment-name> -o yaml -n <namespace>",
            "purpose": "Review resource requests and limits in deployment spec",
        },
        {
            "command": (
                "kubectl set resources deployment <deployment-name> "
                "--limits=memory=512Mi,cpu=500m -n <namespace>"
            ),
            "purpose": "Update memory and CPU limits for the deployment",
        },
    ],
    "Readiness Probe Failed": [
        {
            "command": "kubectl describe pod <pod-name> -n <namespace>",
            "purpose": "View probe configuration and failure events",
        },
        {
            "command": "kubectl logs <pod-name> -n <namespace>",
            "purpose": "Check application logs for startup errors",
        },
        {
            "command": "kubectl port-forward pod/<pod-name> 8080:8080 -n <namespace>",
            "purpose": "Forward port to test the health endpoint locally",
        },
        {
            "command": "curl http://localhost:8080/health",
            "purpose": "Test the readiness/health endpoint directly",
        },
        {
            "command": "kubectl edit deployment <deployment-name> -n <namespace>",
            "purpose": "Edit probe configuration (path, port, timing)",
        },
    ],
    "Liveness Probe Failed": [
        {
            "command": "kubectl describe pod <pod-name> -n <namespace>",
            "purpose": "View liveness probe configuration and failure details",
        },
        {
            "command": "kubectl logs <pod-name> -n <namespace>",
            "purpose": "Check application logs for health check failures",
        },
        {
            "command": "kubectl port-forward pod/<pod-name> 8080:8080 -n <namespace>",
            "purpose": "Forward port to test the liveness endpoint locally",
        },
        {
            "command": "curl http://localhost:8080/health",
            "purpose": "Verify the health endpoint returns a 200 response",
        },
        {
            "command": "kubectl edit deployment <deployment-name> -n <namespace>",
            "purpose": "Adjust liveness probe timing and threshold",
        },
    ],
    "Pending Pod": [
        {
            "command": "kubectl describe pod <pod-name> -n <namespace>",
            "purpose": "View scheduling failure reasons in pod events",
        },
        {
            "command": "kubectl get nodes",
            "purpose": "List all nodes and their status",
        },
        {
            "command": "kubectl top nodes",
            "purpose": "Check available resources on each node",
        },
        {
            "command": "kubectl describe node <node-name>",
            "purpose": "View node conditions, taints, and allocatable resources",
        },
        {
            "command": "kubectl get pvc -n <namespace>",
            "purpose": "Check PersistentVolumeClaim status (Bound/Pending)",
        },
        {
            "command": "kubectl get resourcequota -n <namespace>",
            "purpose": "Check if resource quotas are blocking pod scheduling",
        },
    ],
    "Node Pressure": [
        {
            "command": "kubectl describe node <node-name>",
            "purpose": "View node conditions and pressure details",
        },
        {
            "command": "kubectl top nodes",
            "purpose": "Check memory, CPU, and disk utilization across nodes",
        },
        {
            "command": "kubectl get pods -A -o wide",
            "purpose": "List all pods across namespaces with node placement",
        },
        {
            "command": (
                "kubectl drain <node-name> "
                "--ignore-daemonsets --delete-emptydir-data"
            ),
            "purpose": "Safely drain a node to reschedule pods elsewhere",
        },
        {
            "command": "kubectl cordon <node-name>",
            "purpose": "Mark a node as unschedulable to prevent new pods",
        },
    ],
    "DNS Failure": [
        {
            "command": "kubectl get pods -n kube-system",
            "purpose": "Check if CoreDNS pods are running and healthy",
        },
        {
            "command": "kubectl logs -n kube-system -l k8s-app=kube-dns",
            "purpose": "View CoreDNS logs for errors",
        },
        {
            "command": (
                "kubectl exec -it <pod-name> -n <namespace> "
                "-- nslookup <service-name>"
            ),
            "purpose": "Test DNS resolution from inside a pod",
        },
        {
            "command": "kubectl get svc -A",
            "purpose": "List all services across namespaces to verify service names",
        },
        {
            "command": "kubectl get networkpolicy -A",
            "purpose": "Check if NetworkPolicies are blocking DNS traffic",
        },
    ],
}


def get_commands(findings: list[dict]) -> list[dict]:
    """Generate kubectl command recommendations for each unique issue type found.

    Args:
        findings: List of finding dicts from the rule analyzer.

    Returns:
        List of dicts with issue_type, command, and purpose.
    """
    seen_types = set()
    commands = []

    for finding in findings:
        issue_type = finding["issue_type"]
        if issue_type in seen_types:
            continue
        seen_types.add(issue_type)

        issue_commands = COMMAND_MAP.get(issue_type, [])
        for cmd in issue_commands:
            commands.append({
                "issue_type": issue_type,
                "command": cmd["command"],
                "purpose": cmd["purpose"],
            })

    return commands
