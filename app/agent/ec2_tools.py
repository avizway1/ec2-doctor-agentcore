"""Read-only EC2 diagnostic tools for the EC2 Doctor agent.

Every tool makes Describe*/Get* calls only, and every client is pinned
to one region. The agent can look, but it cannot change anything.
"""
import functools
import json
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError
from strands import tool

REGION = "ap-south-1"  # Mumbai only

ec2 = boto3.client("ec2", region_name=REGION)
cloudwatch = boto3.client("cloudwatch", region_name=REGION)
ssm = boto3.client("ssm", region_name=REGION)

RISKY_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"}


def _safe(fn):
    """Return AWS errors to the model as data instead of crashing the tool."""
    @functools.wraps(fn)  # keeps the name, docstring and signature for the tool schema
    def wrapper(*args, **kwargs):
        try:
            return json.dumps(fn(*args, **kwargs), default=str)
        except ClientError as e:
            err = e.response["Error"]
            return json.dumps({"error": err["Code"], "message": err["Message"]})
    return wrapper


def _instance(instance_id: str) -> dict:
    res = ec2.describe_instances(InstanceIds=[instance_id])
    return res["Reservations"][0]["Instances"][0]


@tool
@_safe
def describe_instance(instance_id: str) -> dict:
    """Get the core configuration of one EC2 instance: state, type, network
    placement, public IP, IMDS settings, IAM profile and key pair.

    Args:
        instance_id: The EC2 instance ID, for example i-0abc1234567890def
    """
    i = _instance(instance_id)
    return {
        "instance_id": instance_id,
        "name": next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "Name"), None),
        "state": i["State"]["Name"],
        "instance_type": i["InstanceType"],
        "availability_zone": i["Placement"]["AvailabilityZone"],
        "launch_time": i["LaunchTime"],
        "vpc_id": i.get("VpcId"),
        "subnet_id": i.get("SubnetId"),
        "private_ip": i.get("PrivateIpAddress"),
        "public_ip": i.get("PublicIpAddress"),
        "key_pair": i.get("KeyName"),
        "iam_instance_profile": i.get("IamInstanceProfile", {}).get("Arn"),
        "imds_http_tokens": i["MetadataOptions"]["HttpTokens"],  # 'required' means IMDSv2 only
        "imds_hop_limit": i["MetadataOptions"]["HttpPutResponseHopLimit"],
        "detailed_monitoring": i["Monitoring"]["State"],
        "security_group_ids": [g["GroupId"] for g in i["SecurityGroups"]],
    }


@tool
@_safe
def check_status_checks(instance_id: str) -> dict:
    """Get the system and instance status checks, plus any scheduled events.

    Args:
        instance_id: The EC2 instance ID
    """
    res = ec2.describe_instance_status(InstanceIds=[instance_id], IncludeAllInstances=True)
    s = res["InstanceStatuses"][0]
    return {
        "state": s["InstanceState"]["Name"],
        "system_status": s["SystemStatus"]["Status"],      # AWS hardware / network side
        "instance_status": s["InstanceStatus"]["Status"],  # OS side
        "scheduled_events": s.get("Events", []),
    }


@tool
@_safe
def get_cpu_metrics(instance_id: str, hours: int = 24) -> dict:
    """Get CPU utilization (average and peak) for the last N hours. For
    burstable T-family instances it also returns the CPU credit balance.

    Args:
        instance_id: The EC2 instance ID
        hours: How many hours to look back (default 24)
    """
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    dim = [{"Name": "InstanceId", "Value": instance_id}]

    def query(qid, metric, stat):
        return {"Id": qid, "ReturnData": True, "MetricStat": {
            "Metric": {"Namespace": "AWS/EC2", "MetricName": metric, "Dimensions": dim},
            "Period": 300, "Stat": stat}}

    res = cloudwatch.get_metric_data(
        StartTime=start, EndTime=end,
        MetricDataQueries=[
            query("cpu_avg", "CPUUtilization", "Average"),
            query("cpu_max", "CPUUtilization", "Maximum"),
            query("credits", "CPUCreditBalance", "Average"),
        ])
    v = {r["Id"]: r["Values"] for r in res["MetricDataResults"]}
    if not v["cpu_avg"]:
        return {"hours": hours, "datapoints": 0, "note": "No CloudWatch data yet for this window"}
    return {
        "hours": hours,
        "datapoints": len(v["cpu_avg"]),
        "cpu_average_percent": round(sum(v["cpu_avg"]) / len(v["cpu_avg"]), 2),
        "cpu_peak_percent": round(max(v["cpu_max"]), 2),
        "cpu_credit_balance_latest": round(v["credits"][0], 1) if v["credits"] else None,
    }


@tool
@_safe
def audit_security_groups(instance_id: str) -> dict:
    """List the inbound rules of every security group attached to the instance
    and flag sensitive ports that are open to the whole internet.

    Args:
        instance_id: The EC2 instance ID
    """
    group_ids = [g["GroupId"] for g in _instance(instance_id)["SecurityGroups"]]
    groups = ec2.describe_security_groups(GroupIds=group_ids)["SecurityGroups"]
    rules, findings = [], []
    for g in groups:
        for p in g["IpPermissions"]:
            sources = [r["CidrIp"] for r in p.get("IpRanges", [])] + \
                      [r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])] + \
                      [r["GroupId"] for r in p.get("UserIdGroupPairs", [])]
            lo, hi = p.get("FromPort", 0), p.get("ToPort", 65535)
            rules.append({"group": g["GroupId"], "protocol": p["IpProtocol"],
                          "ports": f"{lo}-{hi}", "sources": sources})
            if any(s in ("0.0.0.0/0", "::/0") for s in sources):
                for port, name in RISKY_PORTS.items():
                    if p["IpProtocol"] == "-1" or lo <= port <= hi:
                        findings.append(f"{name} (port {port}) is open to the internet in {g['GroupId']}")
    return {"security_groups": group_ids, "inbound_rules": rules, "open_to_world": findings}


@tool
@_safe
def check_volumes(instance_id: str) -> dict:
    """List the EBS volumes attached to the instance with their type, size
    and encryption status.

    Args:
        instance_id: The EC2 instance ID
    """
    vols = ec2.describe_volumes(
        Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}])["Volumes"]
    return {"volumes": [{
        "volume_id": v["VolumeId"],
        "device": v["Attachments"][0]["Device"],
        "type": v["VolumeType"],
        "size_gb": v["Size"],
        "encrypted": v["Encrypted"],
        "delete_on_termination": v["Attachments"][0]["DeleteOnTermination"],
    } for v in vols]}


@tool
@_safe
def check_ssm_managed(instance_id: str) -> dict:
    """Check whether the instance is registered with AWS Systems Manager,
    which allows shell access through Session Manager without opening SSH.

    Args:
        instance_id: The EC2 instance ID
    """
    info = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])["InstanceInformationList"]
    if not info:
        return {"ssm_managed": False,
                "hint": "No SSM registration. Usually a missing instance profile with "
                        "AmazonSSMManagedInstanceCore, or no route to the SSM endpoints."}
    return {"ssm_managed": True, "ping_status": info[0]["PingStatus"],
            "agent_version": info[0]["AgentVersion"], "platform": info[0].get("PlatformName")}


EC2_TOOLS = [describe_instance, check_status_checks, get_cpu_metrics,
             audit_security_groups, check_volumes, check_ssm_managed]
