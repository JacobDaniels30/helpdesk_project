#!/usr/bin/env python3

# Read the original template
with open("templates/agent_ticket_detail.html", "r", encoding="utf-8") as f:
    content = f.read()

# Define the old and new comment sections
old_comment_section = """                    {% for comment in comments %}
                    <div class="chat-bubble {% if comment.commenter_role == 'user' %}chat-user{% else %}chat-agent{% endif %}" id="comment-{{ comment.id }}">
                        <div class="chat-header">
                            <strong>{{ comment.commenter_name }}</strong> <span class="chat-role">({{ comment.commenter_role }})</span>
                            <span class="chat-timestamp" title="{{ comment.created_at.strftime('%Y-%m-%d %H:%M:%S') }}">{{ comment.created_at.strftime('%H:%M, %d-%m-%Y') }}</span>
                        </div>
                        <div class="chat-message">{{ comment.comment|safe }}</div>
                    </div>
                    {% endfor %}"""

new_comment_section = """                    {% for comment in comments %}
                    <div class="comment-bubble {% if comment.commenter_role == 'user' %}comment-user{% else %}comment-agent{% endif %}" id="comment-{{ comment.id }}">
                        <div class="comment-header">
                            <strong>{{ comment.commenter_name }}</strong> <span class="comment-role">({{ comment.commenter_role }})</span>
                        </div>
                        <div class="comment-message">{{ comment.comment|safe }}</div>
                    </div>
                    {% endfor %}"""

# Replace the old section with the new one
updated_content = content.replace(old_comment_section, new_comment_section)

# Write the updated content back to the file
with open("templates/agent_ticket_detail.html", "w", encoding="utf-8") as f:
    f.write(updated_content)

print("Template updated successfully!")
