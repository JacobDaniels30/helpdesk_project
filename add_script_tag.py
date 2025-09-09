#!/usr/bin/env python3

# Read the template
with open("templates/agent_ticket_detail.html", "r", encoding="utf-8") as f:
    content = f.read()

# Add the script tag after the existing link tags
script_tag = ""

# Find the position after the last link tag
link_end_pos = content.rfind("</link>")
if link_end_pos != -1:
    # Insert after the last link tag
    updated_content = (
        content[: link_end_pos + 7] + "\n" + script_tag + content[link_end_pos + 7 :]
    )
else:
    # Fallback: insert after the head section
    head_end_pos = content.find("</head>")
    if head_end_pos != -1:
        updated_content = (
            content[:head_end_pos] + script_tag + "\n" + content[head_end_pos:]
        )
    else:
        updated_content = content

# Write back
with open("templates/agent_ticket_detail.html", "w", encoding="utf-8") as f:
    f.write(updated_content)

print("Script tag added successfully!")
