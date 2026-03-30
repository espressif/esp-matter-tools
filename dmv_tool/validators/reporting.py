#!/usr/bin/env python3

# Copyright 2025 Espressif Systems (Shanghai) PTE LTD
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import io


def _count_clusters_shown_in_conformance_table(dt: dict) -> int:
    """Clusters listed for one device type in the detailed conformance table (present, not optional-only).

    The per-endpoint device-type summary row adds endpoint ``extra_clusters`` once to the
    first non-skipped device type so the count matches total clusters on that endpoint.
    """
    n = 0
    for c in dt.get("cluster_validations", []) or []:
        if not isinstance(c, dict):
            continue
        if not c.get("cluster_present", True):
            continue
        if c.get("cluster_required") is False:
            continue
        n += 1
    return n


def generate_conformance_report(
    validation_data, detected_version=None, version_auto_detected=False
):
    """Generate the conformance report.

    Args:
        validation_data: Validation results data
        detected_version: The spec version used for validation
        version_auto_detected: Whether version was auto-detected

    Returns:
        Formatted conformance report as string
    """
    old_stdout = sys.stdout
    sys.stdout = captured_output = io.StringIO()

    try:
        print_conformance_summary(
            validation_data, detected_version, version_auto_detected
        )
        report_text = captured_output.getvalue()
    finally:
        sys.stdout = old_stdout

    return report_text


def print_table(headers, rows, title=None):
    """Print a formatted table using tabulate if available, otherwise simple format

    Args:
        headers: The headers of the table
        rows: The rows of the table
        title: The title of the table

    """
    if title:
        print(f"\n{title}")
        print("=" * len(title))

        col_widths = [
            max(len(str(header)), max(len(str(row[i])) for row in rows) if rows else 0)
            for i, header in enumerate(headers)
        ]

        header_row = " | ".join(
            str(header).ljust(col_widths[i]) for i, header in enumerate(headers)
        )
        print(header_row)
        print("-" * len(header_row))

        for row in rows:
            row_str = " | ".join(
                str(row[i]).ljust(col_widths[i]) for i in range(len(headers))
            )
            print(row_str)
    print()


def format_missing_element(elem: dict) -> str:
    name = elem.get("name", "Unknown")
    elem_type = elem.get("type", "Unknown")
    cluster = elem.get("cluster_name", "Unknown")
    device_type = elem.get("device_type_name", "Unknown")
    message = elem.get("message", "")

    if elem_type in (
        "attribute",
        "command",
        "feature",
        "feature_attribute",
        "feature_command",
        "feature_event",
    ):
        return f"\t   • {name} {elem_type} is missing on {cluster} cluster. {message}"
    elif elem_type == "cluster":
        return f"\t   • {cluster} cluster is missing on {device_type} device type."
    else:
        return f"\t   • {name} is missing on {cluster} cluster. {message}"


def format_duplicate_element(elem: dict) -> str:
    name = elem.get("name", "Unknown")
    elem_id = elem.get("id", "Unknown")
    count = elem.get("count", 2)
    cluster = elem.get("cluster_name", "Unknown")

    return f"\t   • {name} ({elem_id}) appears {count} times in {cluster} cluster"


def print_conformance_summary(
    validation_data, detected_version=None, version_auto_detected=False
):
    """Print comprehensive conformance summary in tabular format with per-endpoint details.

    Args:
        validation_data: Validation results data
        detected_version: The spec version used for validation
        version_auto_detected: Whether version was auto-detected
    """
    if not validation_data:
        print("No validation data available")
        return

    summary = validation_data.get("summary", {})
    endpoints = validation_data.get("endpoints", [])

    total_endpoints = summary.get("total_endpoints", 0)
    compliant_endpoints = summary.get("compliant_endpoints", 0)
    non_compliant_endpoints = summary.get("non_compliant_endpoints", 0)
    total_revision_issues = summary.get("total_revision_issues", 0)
    total_event_warnings = summary.get("total_event_warnings", 0)
    total_duplicate_elements = summary.get("total_duplicate_elements", 0)
    total_extra_clusters = summary.get("total_extra_clusters", 0)

    print("\n" + "=" * 80)
    print("MATTER DEVICE CONFORMANCE REPORT")
    print("=" * 80)

    if detected_version:
        print("\nVERSION DETECTION")
        print("=" * 30)
        if version_auto_detected:
            print(f"Auto-detected spec version: {detected_version}")
            print("   (Detected from SpecificationVersion in wildcard logs)")
        else:
            print(f"Using specified spec version: {detected_version}")
        print(f"Validation against Matter {detected_version} specification")

    conformance_rate = (
        (compliant_endpoints / total_endpoints * 100) if total_endpoints > 0 else 0
    )
    overall_status = "COMPLIANT" if non_compliant_endpoints == 0 else "NON-COMPLIANT"
    summary_data = [
        ["Total Endpoints", total_endpoints],
        ["Compliant Endpoints", compliant_endpoints],
        ["Non-Compliant Endpoints", non_compliant_endpoints],
        ["Conformance Rate", f"{conformance_rate:.1f}%"],
        ["Total Duplicate Elements", total_duplicate_elements],
        ["Total Revision Issues", total_revision_issues],
        ["Total Event Warnings", total_event_warnings],
    ]

    if total_extra_clusters > 0:
        summary_data.append(["Extra Clusters (informational)", total_extra_clusters])

    summary_data.append(["Overall Status", overall_status])

    print_table(["Metric", "Value"], summary_data, "OVERALL CONFORMANCE SUMMARY")

    print("\n" + "=" * 80)
    print("📋 PER-ENDPOINT DETAILED CONFORMANCE ANALYSIS")
    print("=" * 80)

    for i, endpoint in enumerate(endpoints):
        endpoint_id = endpoint.get("endpoint", "Unknown")
        is_compliant = endpoint.get("is_compliant", False)
        device_types = endpoint.get("device_types", [])
        missing_elements = endpoint.get("missing_elements", [])
        event_warnings = endpoint.get("event_warnings", [])

        if device_types:
            device_type_rows = []
            extra_n = len(
                [
                    x
                    for x in (endpoint.get("extra_clusters") or [])
                    if isinstance(x, dict)
                ]
            )
            extras_attributed = False
            for dt in device_types:
                if not isinstance(dt, dict):
                    device_type_rows.append(
                        [
                            "Error",
                            "Error",
                            "Error",
                            0,
                            f"Invalid device type format: {type(dt)} - {str(dt)[:50]}...",
                        ]
                    )
                    continue

                if "error" in dt:
                    device_type_rows.append(
                        [
                            "Error",
                            "Error",
                            "Error",
                            0,
                            dt.get("error", "Unknown error")[:50] + "...",
                        ]
                    )
                else:
                    dt_id = dt.get("device_type_id", "Unknown")
                    dt_name = dt.get("device_type_name", "Unknown")
                    dt_compliant = dt.get("is_compliant", False)
                    clusters_count = _count_clusters_shown_in_conformance_table(dt)
                    if (
                        extra_n
                        and not extras_attributed
                        and not dt.get("skipped")
                    ):
                        clusters_count += extra_n
                        extras_attributed = True

                    status = "Compliant" if dt_compliant else "Non-Compliant"

                    device_type_rows.append([dt_id, dt_name, status, clusters_count])

            print_table(
                ["Device Type ID", "Device Type Name", "Status", "Clusters"],
                device_type_rows,
                f"📋 Endpoint {endpoint_id} Device Types",
            )

        cluster_rows = []
        for dt in device_types:
            if not isinstance(dt, dict) or "cluster_validations" not in dt:
                continue

            for cluster in dt.get("cluster_validations", []):
                if not isinstance(cluster, dict):
                    continue

                # Skip clusters that don't actually exist on the device
                cluster_present = cluster.get("cluster_present", True)
                if not cluster_present:
                    continue

                # Fully optional spec entries are omitted from cluster_validations;
                # skip if present in older saved JSON
                if cluster.get("cluster_required") is False:
                    continue

                cluster_id = cluster.get("cluster_id", "Unknown")
                cluster_name = cluster.get("cluster_name", "Unknown")
                cluster_type = cluster.get("cluster_type", "server")
                device_type_name = dt.get("device_type_name", "Unknown")
                is_cluster_compliant = cluster.get("is_compliant", False)

                cluster_revision_issues = cluster.get("revision_issues", [])
                revision_summary = ""
                if cluster_revision_issues:
                    error_count = len(
                        [
                            r
                            for r in cluster_revision_issues
                            if isinstance(r, dict) and r.get("severity") == "error"
                        ]
                    )
                    warning_count = len(
                        [
                            r
                            for r in cluster_revision_issues
                            if isinstance(r, dict) and r.get("severity") != "error"
                        ]
                    )
                    if error_count > 0:
                        revision_summary = f"{error_count} errors"
                        if warning_count > 0:
                            revision_summary += f", {warning_count} warnings"
                    elif warning_count > 0:
                        revision_summary = f"{warning_count} warnings"
                else:
                    revision_summary = "OK"

                status = "Compliant" if is_cluster_compliant else "Non-Compliant"

                cluster_rows.append(
                    [
                        cluster_id,
                        cluster_name,
                        cluster_type.title(),
                        device_type_name,
                        status,
                        revision_summary,
                    ]
                )
        if cluster_rows:
            print_table(
                [
                    "Cluster ID",
                    "Cluster Name",
                    "Type",
                    "Device Type Name",
                    "Status",
                    "Revisions",
                ],
                cluster_rows,
                f"🔧 Endpoint {endpoint_id} Complete Cluster Conformance",
            )

        extra_cluster_rows = []
        for extra in endpoint.get("extra_clusters", []):
            if not isinstance(extra, dict):
                continue
            extra_cluster_rows.append(
                [
                    extra.get("cluster_id", "Unknown"),
                    extra.get("cluster_name", "Unknown"),
                    (extra.get("cluster_type") or "server").title(),
                    extra.get(
                        "message",
                        "Not required by any device type on this endpoint",
                    ),
                ]
            )
        if extra_cluster_rows:
            print_table(
                [
                    "Cluster ID",
                    "Cluster Name",
                    "Type",
                    "Note",
                ],
                extra_cluster_rows,
                f"Endpoint {endpoint_id} Extra Clusters (not required by any device type)",
            )

        endpoint_level_warnings = [
            w
            for w in event_warnings
            if isinstance(w, dict) and not w.get("cluster_name")
        ]
        if endpoint_level_warnings:
            event_rows = []
            for warning in endpoint_level_warnings:
                severity = warning.get("severity", "info")
                severity_text = "Warning" if severity == "warning" else "Info"

                event_rows.append(
                    [
                        warning.get("type", "Unknown"),
                        f"{severity_text}",
                        (
                            warning.get("message", "")[:60] + "..."
                            if len(warning.get("message", "")) > 60
                            else warning.get("message", "")
                        ),
                    ]
                )

            print_table(
                ["Event Type", "Severity", "Message"],
                event_rows,
                f"Endpoint {endpoint_id} General Event Warnings",
            )

        duplicate_elements = endpoint.get("duplicate_elements", [])

        print(f"\nEndpoint {endpoint_id} Recommendations:")
        if not is_compliant:
            device_revision_issue = endpoint.get("revision_issues", [])
            if device_revision_issue:
                print(
                    f"\n   • Fix {len(device_revision_issue)} revision issue(s) listed below"
                )
                for revision_issue in device_revision_issue:
                    if isinstance(revision_issue, dict):
                        print(
                            f"\t   • For {revision_issue.get('item_name', 'Unknown')}, revision on device is {revision_issue.get('actual_revision', 'Unknown')} but the required revision is {revision_issue.get('required_revision', 'Unknown')}"
                        )

            if missing_elements:
                print(
                    f"\n   • Fix {len(missing_elements)} missing element(s) listed below"
                )
                print(
                    "   • Make sure to add the missing elements to the "
                    "respective clusters"
                )
                for missing_element in missing_elements:
                    if isinstance(missing_element, dict):
                        print(format_missing_element(missing_element))

            if duplicate_elements:
                print(
                    f"\n   • Remove {len(duplicate_elements)} duplicate element(s) listed below"
                )
                for dup_element in duplicate_elements:
                    if isinstance(dup_element, dict):
                        print(format_duplicate_element(dup_element))

            total_cluster_revision_errors = 0
            for dt in device_types:
                if isinstance(dt, dict):
                    for cluster in dt.get("cluster_validations", []):
                        if isinstance(cluster, dict):
                            cluster_revision_issues = cluster.get("revision_issues", [])
                            total_cluster_revision_errors += len(
                                [
                                    r
                                    for r in cluster_revision_issues
                                    if isinstance(r, dict)
                                    and r.get("severity") == "error"
                                ]
                            )

        else:
            print("   • Endpoint is compliant - no action needed")

        if event_warnings:
            print(
                "\n   • Make sure the below events are present on the device "
                "(informational only)"
            )
            for event_warning in event_warnings:
                if isinstance(event_warning, dict):
                    (
                        print(
                            f"\t   •{event_warning.get('event_name', 'Unknown')} event is present on {event_warning.get('cluster_name', 'Unknown')} cluster"
                        )
                        if event_warning.get("type", "unknown") == "event_requirement"
                        else None
                    )

    print(f"\n{'=' * 80}")
    print("RECOMMENDATIONS")
    print(f"{'=' * 80}")

    if non_compliant_endpoints > 0:
        print(f"• Fix conformance issues in {non_compliant_endpoints} endpoint(s)")
        print("• Focus on endpoints marked as Non-Compliant above")
        print("• Check per-endpoint missing elements and revision issues")
        if total_revision_issues > 0:
            print(
                "• Update all cluster and device type revisions to meet required revisions"
            )
        if total_duplicate_elements > 0:
            print(
                f"• Remove {total_duplicate_elements} duplicate element(s) from device clusters"
            )
        if total_duplicate_elements > 0:
            print(
                f"• Remove {total_duplicate_elements} duplicate element(s) from device clusters"
            )
    else:
        print("• All required data model elements are present on the device")

    if total_extra_clusters > 0:
        print(
            f"• {total_extra_clusters} extra cluster(s) on device (not required by any "
            "device type on that endpoint; informational only)"
        )

    if total_event_warnings > 0:
        print(
            f"• Review {total_event_warnings} event warnings (don't affect conformance)"
        )

    print("\nDetailed results saved in:")
    print("   • output/parsed_data.json - Raw parsed device data")
    print("   • output/validation_results.json - Complete validation results")
    print("=" * 80)
