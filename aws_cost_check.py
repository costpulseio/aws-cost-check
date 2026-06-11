#!/usr/bin/env python3
"""
aws-cost-check — 60-second AWS waste scan. Read-only. No agents. No excuses.

Runs entirely with read-only API calls and prints an estimated annualized
waste figure for the most common AWS money leaks:

  1. gp2 EBS volumes that should be gp3        (~20% cheaper, same perf)
  2. Unattached EBS volumes                    (paying for disks doing nothing)
  3. Idle NAT gateways                         ($32+/mo each, even at 0 bytes)
  4. Unassociated Elastic IPs                  (charged when NOT in use)
  5. Stopped EC2 instances w/ attached storage (the "we'll need it later" tax)
  6. Underutilized EC2 (avg CPU < 10%, 14d)    (rightsizing candidates)
  7. Idle RDS instances (~0 connections, 14d)  (databases nobody talks to)
  8. Savings Plan / RI coverage gap            (paying on-demand for steady load)

Usage (AWS CloudShell is the easiest — boto3 is preinstalled):

    python3 aws_cost_check.py                 # scan default + all enabled regions
    python3 aws_cost_check.py --regions us-east-1,us-west-2
    python3 aws_cost_check.py --json          # machine-readable output

Required permissions: ec2:Describe*, cloudwatch:GetMetricStatistics,
rds:DescribeDBInstances, ce:GetSavingsPlansCoverage (optional check),
sts:GetCallerIdentity. The AWS-managed ViewOnlyAccess policy covers all of it.

All dollar figures are ESTIMATES based on typical us-east-1 on-demand pricing.
Your real savings are usually higher. For the line-by-line audited version:

    https://costpulse.io/audit

(c) CostPulse LLC — MIT License. PRs welcome.
"""

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    sys.exit("boto3 is required. Run inside AWS CloudShell or `pip install boto3`.")

# ── Rough monthly price assumptions (us-east-1 on-demand, USD) ──────────────
PRICE = {
    "gp2_gb_month": 0.10,
    "gp3_gb_month": 0.08,
    "nat_gw_month": 32.85,          # hourly charge only; data processing extra
    "eip_month": 3.65,              # idle public IPv4
    "ebs_gb_month_avg": 0.09,       # blended estimate for stopped-instance storage
    "rds_idle_month_floor": 50.0,   # conservative floor per idle RDS instance
    "cpu_rightsize_factor": 0.40,   # assume ~40% savings on rightsized instances
}

# Very rough on-demand monthly cost by instance family size for rightsizing math.
INSTANCE_MONTHLY = {
    "nano": 4, "micro": 8, "small": 15, "medium": 30, "large": 60,
    "xlarge": 120, "2xlarge": 240, "4xlarge": 480, "8xlarge": 960,
    "12xlarge": 1440, "16xlarge": 1920, "24xlarge": 2880,
}


def monthly_cost_guess(instance_type: str) -> float:
    size = instance_type.split(".")[-1] if "." in instance_type else instance_type
    return INSTANCE_MONTHLY.get(size, 60)


def annual(monthly: float) -> float:
    return monthly * 12


class Finding:
    def __init__(self, check, region, resource, detail, annual_savings):
        self.check = check
        self.region = region
        self.resource = resource
        self.detail = detail
        self.annual_savings = annual_savings

    def as_dict(self):
        return {
            "check": self.check,
            "region": self.region,
            "resource": self.resource,
            "detail": self.detail,
            "estimated_annual_savings_usd": round(self.annual_savings, 2),
        }


def safe(fn):
    """Run a check; on AccessDenied or API error, report and move on."""
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            print(f"  [skip] {fn.__name__}: {code}", file=sys.stderr)
            return []
        except Exception as e:  # noqa: BLE001 — keep the scan alive
            print(f"  [skip] {fn.__name__}: {e}", file=sys.stderr)
            return []
    return wrapper


# ── Checks ───────────────────────────────────────────────────────────────────

@safe
def check_gp2_volumes(session, region):
    ec2 = session.client("ec2", region_name=region)
    findings = []
    for page in ec2.get_paginator("describe_volumes").paginate(
        Filters=[{"Name": "volume-type", "Values": ["gp2"]}]
    ):
        for v in page["Volumes"]:
            size = v["Size"]
            saving = annual(size * (PRICE["gp2_gb_month"] - PRICE["gp3_gb_month"]))
            findings.append(Finding(
                "gp2 → gp3 migration", region, v["VolumeId"],
                f"{size} GiB gp2 (gp3 is ~20% cheaper, equal/better baseline perf)",
                saving,
            ))
    return findings


@safe
def check_unattached_volumes(session, region):
    ec2 = session.client("ec2", region_name=region)
    findings = []
    for page in ec2.get_paginator("describe_volumes").paginate(
        Filters=[{"Name": "status", "Values": ["available"]}]
    ):
        for v in page["Volumes"]:
            saving = annual(v["Size"] * PRICE["ebs_gb_month_avg"])
            findings.append(Finding(
                "Unattached EBS volume", region, v["VolumeId"],
                f"{v['Size']} GiB '{v['VolumeType']}' attached to nothing "
                f"(created {v['CreateTime'].date()})",
                saving,
            ))
    return findings


@safe
def check_idle_nat_gateways(session, region):
    ec2 = session.client("ec2", region_name=region)
    cw = session.client("cloudwatch", region_name=region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=14)
    findings = []
    for page in ec2.get_paginator("describe_nat_gateways").paginate(
        Filters=[{"Name": "state", "Values": ["available"]}]
    ):
        for nat in page["NatGateways"]:
            stats = cw.get_metric_statistics(
                Namespace="AWS/NATGateway", MetricName="BytesOutToDestination",
                Dimensions=[{"Name": "NatGatewayId", "Value": nat["NatGatewayId"]}],
                StartTime=start, EndTime=end, Period=86400, Statistics=["Sum"],
            )
            total_bytes = sum(p["Sum"] for p in stats.get("Datapoints", []))
            if total_bytes < 1_000_000_000:  # <1 GB out in 14 days = basically idle
                findings.append(Finding(
                    "Idle NAT gateway", region, nat["NatGatewayId"],
                    f"{total_bytes / 1e6:.0f} MB out in 14 days — "
                    "consider VPC endpoints or consolidation",
                    annual(PRICE["nat_gw_month"]),
                ))
    return findings


@safe
def check_unassociated_eips(session, region):
    ec2 = session.client("ec2", region_name=region)
    findings = []
    for addr in ec2.describe_addresses()["Addresses"]:
        if "AssociationId" not in addr:
            findings.append(Finding(
                "Unassociated Elastic IP", region,
                addr.get("AllocationId", addr.get("PublicIp", "unknown")),
                f"{addr.get('PublicIp', '?')} allocated but attached to nothing",
                annual(PRICE["eip_month"]),
            ))
    return findings


@safe
def check_stopped_instances(session, region):
    ec2 = session.client("ec2", region_name=region)
    findings = []
    for page in ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
    ):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                vol_ids = [
                    bdm["Ebs"]["VolumeId"]
                    for bdm in inst.get("BlockDeviceMappings", [])
                    if "Ebs" in bdm
                ]
                if not vol_ids:
                    continue
                vols = ec2.describe_volumes(VolumeIds=vol_ids)["Volumes"]
                gb = sum(v["Size"] for v in vols)
                findings.append(Finding(
                    "Stopped instance w/ storage", region, inst["InstanceId"],
                    f"{inst['InstanceType']} stopped, still paying for "
                    f"{gb} GiB EBS — snapshot & terminate if truly parked",
                    annual(gb * PRICE["ebs_gb_month_avg"]),
                ))
    return findings


@safe
def check_underutilized_ec2(session, region):
    ec2 = session.client("ec2", region_name=region)
    cw = session.client("cloudwatch", region_name=region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=14)
    findings = []
    for page in ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    ):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                stats = cw.get_metric_statistics(
                    Namespace="AWS/EC2", MetricName="CPUUtilization",
                    Dimensions=[{"Name": "InstanceId", "Value": inst["InstanceId"]}],
                    StartTime=start, EndTime=end, Period=86400, Statistics=["Average"],
                )
                points = stats.get("Datapoints", [])
                if not points:
                    continue
                avg_cpu = sum(p["Average"] for p in points) / len(points)
                if avg_cpu < 10.0:
                    itype = inst["InstanceType"]
                    saving = annual(
                        monthly_cost_guess(itype) * PRICE["cpu_rightsize_factor"]
                    )
                    findings.append(Finding(
                        "Underutilized EC2 (rightsize)", region, inst["InstanceId"],
                        f"{itype} averaging {avg_cpu:.1f}% CPU over 14 days",
                        saving,
                    ))
    return findings


@safe
def check_idle_rds(session, region):
    rds = session.client("rds", region_name=region)
    cw = session.client("cloudwatch", region_name=region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=14)
    findings = []
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            if db.get("DBInstanceStatus") != "available":
                continue
            stats = cw.get_metric_statistics(
                Namespace="AWS/RDS", MetricName="DatabaseConnections",
                Dimensions=[{
                    "Name": "DBInstanceIdentifier",
                    "Value": db["DBInstanceIdentifier"],
                }],
                StartTime=start, EndTime=end, Period=86400, Statistics=["Maximum"],
            )
            points = stats.get("Datapoints", [])
            if points and max(p["Maximum"] for p in points) < 1:
                findings.append(Finding(
                    "Idle RDS instance", region, db["DBInstanceIdentifier"],
                    f"{db['DBInstanceClass']} with ~0 connections for 14 days "
                    "— snapshot & stop/delete",
                    annual(PRICE["rds_idle_month_floor"]),
                ))
    return findings


@safe
def check_savings_plan_coverage(session):
    """Org-level check, runs once (not per region). Needs ce:GetSavingsPlansCoverage."""
    ce = session.client("ce", region_name="us-east-1")
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=30)
    resp = ce.get_savings_plans_coverage(
        TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
        Granularity="MONTHLY",
    )
    findings = []
    for item in resp.get("SavingsPlansCoverages", []):
        cov = item.get("Coverage", {})
        pct = float(cov.get("CoveragePercentage", "100") or 100)
        on_demand = float(cov.get("OnDemandCost", "0") or 0)
        if pct < 60 and on_demand > 100:
            # Assume ~25% savings on 70% of the uncovered steady-state spend.
            est = annual(on_demand * 0.70 * 0.25)
            findings.append(Finding(
                "Low Savings Plan coverage", "global", "compute spend",
                f"Only {pct:.0f}% of eligible compute covered; "
                f"${on_demand:,.0f}/mo running on-demand",
                est,
            ))
    return findings


# ── Runner ───────────────────────────────────────────────────────────────────

REGIONAL_CHECKS = [
    check_gp2_volumes,
    check_unattached_volumes,
    check_idle_nat_gateways,
    check_unassociated_eips,
    check_stopped_instances,
    check_underutilized_ec2,
    check_idle_rds,
]


def enabled_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    resp = ec2.describe_regions(AllRegions=False)
    return sorted(r["RegionName"] for r in resp["Regions"])


def main():
    ap = argparse.ArgumentParser(description="60-second read-only AWS waste scan.")
    ap.add_argument("--regions", help="Comma-separated region list (default: all enabled)")
    ap.add_argument("--json", action="store_true", help="Emit JSON instead of a table")
    ap.add_argument("--profile", help="AWS profile name")
    args = ap.parse_args()

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()

    try:
        ident = session.client("sts").get_caller_identity()
        account = ident["Account"]
    except Exception as e:  # noqa: BLE001
        sys.exit(f"No usable AWS credentials found ({e}). Try AWS CloudShell.")

    regions = (
        [r.strip() for r in args.regions.split(",") if r.strip()]
        if args.regions else enabled_regions(session)
    )

    if not args.json:
        print(f"\naws-cost-check · account {account} · {len(regions)} region(s)")
        print("read-only scan — nothing is modified\n")

    findings = []
    for region in regions:
        if not args.json:
            print(f"scanning {region} ...", file=sys.stderr)
        for check in REGIONAL_CHECKS:
            findings.extend(check(session, region))
    findings.extend(check_savings_plan_coverage(session))

    findings.sort(key=lambda f: f.annual_savings, reverse=True)
    total = sum(f.annual_savings for f in findings)

    if args.json:
        print(json.dumps({
            "account": account,
            "regions": regions,
            "estimated_annual_waste_usd": round(total, 2),
            "findings": [f.as_dict() for f in findings],
        }, indent=2))
        return

    if not findings:
        print("No obvious waste found by the quick checks. Either your account is")
        print("genuinely tight (respect), or the leaks are in the places a script")
        print("can't see. The human audit checks 40+ patterns: costpulse.io/audit\n")
        return

    w = max(len(f.check) for f in findings)
    print(f"{'CHECK'.ljust(w)}  {'REGION'.ljust(14)}  {'RESOURCE'.ljust(24)}  EST $/YR")
    print("-" * (w + 14 + 24 + 14))
    for f in findings:
        print(f"{f.check.ljust(w)}  {f.region.ljust(14)}  "
              f"{f.resource[:24].ljust(24)}  {f.annual_savings:>10,.0f}")
        print(f"{''.ljust(w)}  └─ {f.detail}")
    print("-" * (w + 14 + 24 + 14))
    print(f"{'ESTIMATED ANNUALIZED WASTE'.ljust(w + 42)}  ${total:>9,.0f}\n")
    print("These are quick estimates from 8 checks. A full audit covers 40+ patterns,")
    print("exact pricing, and remediation Terraform — guaranteed 3x the fee or free:")
    print("→ https://costpulse.io/audit\n")


if __name__ == "__main__":
    main()
