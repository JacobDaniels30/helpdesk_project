#!/usr/bin/env python3
"""
Script to fix urgency value consistency in the helpdesk database.
This ensures all urgency values match the SLA policies: Low, Normal, High, Critical
"""

import os

from dotenv import load_dotenv
from supabase import Client, create_client

# Load environment variables
load_dotenv()

# Supabase Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://dcizwjswncdoegeycwpt.supabase.co")
SUPABASE_KEY = os.getenv(
    "SUPABASE_KEY",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRjaXp3anN3bmNkb2VnZXljd3B0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTU2NzYxNDUsImV4cCI6MjA3MTI1MjE0NX0.dclVUNWJU-ez9AavDEGv3WTrIn6ZBIUJrdv--zfQUAQ",
)

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def main():
    print("Checking urgency values in tickets table...")

    # Fetch all tickets to check urgency values
    response = supabase.table("tickets").select("id, urgency").execute()
    tickets = response.data or []

    print(f"Found {len(tickets)} tickets")

    # Valid urgency values
    valid_urgencies = {"Low", "Normal", "High", "Critical"}

    # Track issues
    issues_found = []
    updates_needed = []

    for ticket in tickets:
        urgency = ticket.get("urgency")
        if urgency not in valid_urgencies:
            issues_found.append(
                {
                    "id": ticket["id"],
                    "current_urgency": urgency,
                    "issue": "Invalid urgency value",
                }
            )

            # Determine what it should be
            if urgency:
                # Try to map common variations
                urgency_lower = urgency.lower()
                if urgency_lower in ["low", "l"]:
                    new_urgency = "Low"
                elif urgency_lower in ["normal", "medium", "m", "n"]:
                    new_urgency = "Normal"
                elif urgency_lower in ["high", "h"]:
                    new_urgency = "High"
                elif urgency_lower in ["critical", "urgent", "c"]:
                    new_urgency = "Critical"
                else:
                    new_urgency = "Normal"  # Default
            else:
                new_urgency = "Normal"  # Default for None/empty

            updates_needed.append(
                {
                    "id": ticket["id"],
                    "current_urgency": urgency,
                    "new_urgency": new_urgency,
                }
            )

    if issues_found:
        print(f"\nFound {len(issues_found)} tickets with invalid urgency values:")
        for issue in issues_found:
            print(
                f"  Ticket {issue['id']}: '{issue['current_urgency']}' -> needs fixing"
            )

        print(f"\nWill update {len(updates_needed)} tickets:")
        for update in updates_needed:
            print(
                f"  Ticket {update['id']}: '{update['current_urgency']}' -> '{update['new_urgency']}'"
            )

        # Ask for confirmation
        confirm = (
            input("\nDo you want to proceed with these updates? (y/N): ")
            .strip()
            .lower()
        )
        if confirm == "y":
            # Perform updates
            for update in updates_needed:
                try:
                    supabase.table("tickets").update(
                        {"urgency": update["new_urgency"]}
                    ).eq("id", update["id"]).execute()
                    print(
                        f"  ✓ Updated ticket {update['id']}: '{update['current_urgency']}' -> '{update['new_urgency']}'"
                    )
                except Exception as e:
                    print(f"  ✗ Failed to update ticket {update['id']}: {str(e)}")

            print(f"\nSuccessfully updated {len(updates_needed)} tickets.")
        else:
            print("Update cancelled.")
    else:
        print("All tickets have valid urgency values. No fixes needed.")

    # Also check SLA policies table
    print("\nChecking SLA policies table...")
    sla_response = supabase.table("sla_policies").select("*").execute()
    sla_policies = sla_response.data or []

    print(f"Found {len(sla_policies)} SLA policies:")
    for policy in sla_policies:
        print(
            f"  {policy['urgency']}: Response={policy['response_hours']}h, Resolution={policy['resolution_hours']}h"
        )


if __name__ == "__main__":
    main()
