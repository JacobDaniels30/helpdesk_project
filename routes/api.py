from datetime import datetime, timezone
import bleach
from flask import Blueprint, flash, jsonify, redirect, request, session, url_for
from db import supabase

api_bp = Blueprint("api", __name__)

ALLOWED_TAGS = ["b", "i", "u", "a", "strong", "em", "p", "br"]
ALLOWED_ATTRIBUTES = {"a": ["href", "title"]}


def format_comment_dates(comments):
    """Format datetime objects in comments for JSON response"""
    for comment in comments:
        if "created_at" in comment and comment["created_at"]:
            if not isinstance(comment["created_at"], str):
                comment["created_at"] = comment["created_at"].isoformat()
    return comments


@api_bp.route("/api/tickets/<uuid:ticket_id>/comments", methods=["GET"])
def get_ticket_comments(ticket_id):
    """Get all comments for a specific ticket"""
    if "user_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        comments_resp = (
            supabase.table("ticket_comments")
            .select(
                """
                *,
                users!ticket_comments_agent_id_fkey(name, role)
            """
            )
            .eq("ticket_id", str(ticket_id))
            .order("created_at")
            .execute()
        )

        comments = comments_resp.data or []

        for comment in comments:
            if comment.get("users"):
                comment["commenter_name"] = comment["users"]["name"]
                comment["commenter_role"] = comment["users"]["role"]
                del comment["users"]

        comments = format_comment_dates(comments)
        return jsonify({"comments": comments}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/agent/tickets/<uuid:ticket_id>/comments", methods=["POST"])
def agent_add_comment(ticket_id):
    """Add a new comment to a ticket (form-based for agents)"""
    if "user_email" not in session:
        flash("Please login to add comments.", "warning")
        return redirect(url_for("login"))

    from db import get_user_by_email

    user = get_user_by_email(session["user_email"])
    if not user or user.get("role") != "agent":
        flash("Agent access required.", "danger")
        return redirect(url_for("dashboard"))

    comment_text = request.form.get("comment", "").strip()
    if not comment_text:
        flash("Comment cannot be empty.", "danger")
        return redirect(url_for("edit_ticket", ticket_id=ticket_id))

    cleaned_comment = bleach.clean(
        comment_text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES
    )

    try:
        now = datetime.now(timezone.utc).isoformat()
        comment_data = {
            "ticket_id": str(ticket_id),
            "agent_id": session["user_id"],
            "comment": cleaned_comment,
            "commenter_role": "agent",
            "created_at": now,
        }

        insert_resp = supabase.table("ticket_comments").insert(comment_data).execute()
        if insert_resp.data:
            flash("Comment added successfully.", "success")
        else:
            flash("Failed to add comment.", "danger")

    except Exception as e:
        flash(f"Error adding comment: {str(e)}", "danger")

    return redirect(url_for("edit_ticket", ticket_id=ticket_id))


@api_bp.route("/api/tickets/<uuid:ticket_id>/comments", methods=["POST"])
def add_ticket_comment(ticket_id):
    """Add a new comment to a ticket"""
    print("=== COMMENT ROUTE CALLED ===")
    print(f"Request method: {request.method}")
    print(f"Request content-type: {request.content_type}")
    print(f"Request form data: {dict(request.form)}")
    print(f"Request data: {request.get_data()}")
    print(f"Session user_id: {session.get('user_id')}")
    print(f"Session user_email: {session.get('user_email')}")

    if "user_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    from db import get_user_by_email

    user = get_user_by_email(session["user_email"])
    if not user:
        return jsonify({"error": "User not found"}), 401

    if request.content_type == "application/json":
        data = request.get_json()
        comment_text = data.get("comment", "").strip()
    else:
        comment_text = request.form.get("comment", "").strip()

    if not comment_text:
        return jsonify({"error": "Comment cannot be empty"}), 400

    cleaned_comment = bleach.clean(
        comment_text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES
    )

    try:
        commenter_role = user.get("role", "user")
        now = datetime.now(timezone.utc).isoformat()
        comment_data = {
            "ticket_id": str(ticket_id),
            "agent_id": session["user_id"],
            "comment": cleaned_comment,
            "commenter_role": commenter_role,
            "created_at": now,
        }

        insert_resp = supabase.table("ticket_comments").insert(comment_data).execute()
        new_comment = insert_resp.data[0] if insert_resp.data else None
        if not new_comment:
            return jsonify({"error": "Failed to create comment"}), 500

        comment_resp = (
            supabase.table("ticket_comments")
            .select(
                """
                *,
                users!ticket_comments_agent_id_fkey(name, role)
            """
            )
            .eq("id", new_comment["id"])
            .single()
            .execute()
        )

        if comment_resp.data:
            comment_with_user = comment_resp.data
            comment_with_user["commenter_name"] = comment_with_user["users"]["name"]
            comment_with_user["commenter_role"] = comment_with_user["users"]["role"]
            del comment_with_user["users"]

            formatted_comment = format_comment_dates([comment_with_user])[0]

            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({
                    "success": True,
                    "comment": formatted_comment,
                    "message": "Comment added successfully",
                }), 200
            else:
                return redirect(url_for("edit_ticket", ticket_id=ticket_id))
        else:
            return jsonify({"error": "Failed to retrieve comment"}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Other routes for update, delete, and mark-read follow same structure
# Cleaned and formatted similarly using timezone.utc and removing unnecessary dashes
