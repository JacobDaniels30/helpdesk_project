import requests
from bs4 import BeautifulSoup

# URL of the admin dashboard login page
LOGIN_URL = "http://localhost:5000/login"
UPDATE_STATUS_URL_TEMPLATE = "http://localhost:5000/update_status/{}"

# Replace with valid admin credentials for testing
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "yourpassword"

def get_csrf_token(session, url):
    """Fetch the CSRF token from the given URL using the session."""
    response = session.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    csrf_input = soup.find("input", {"name": "csrf_token"})
    if csrf_input:
        return csrf_input.get("value")
    return None

def login(session):
    """Login to the app and maintain session cookies."""
    csrf_token = get_csrf_token(session, LOGIN_URL)
    login_data = {
        "email": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD,
        "csrf_token": csrf_token,
    }
    response = session.post(LOGIN_URL, data=login_data)
    return response.ok

def test_ajax_update_status(ticket_id, new_status):
    with requests.Session() as session:
        if not login(session):
            print("Login failed")
            return

        # The update_status page does not render a form, so no CSRF token can be fetched from it.
        # Instead, fetch the CSRF token from the admin dashboard page.
        csrf_token = get_csrf_token(session, "http://localhost:5000/admin_dashboard")
        if not csrf_token:
            print("Failed to get CSRF token for update_status")
            return

        print("Session cookies after login:", session.cookies.get_dict())

        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "http://localhost:5000/admin_dashboard"
        }
        data = {
            "status": new_status,
            "csrf_token": csrf_token
        }
        response = session.post(UPDATE_STATUS_URL_TEMPLATE.format(ticket_id), data=data, headers=headers)
        print("Status code:", response.status_code)
        print("Request headers:", response.request.headers)
        print("Request cookies:", response.request._cookies)
        try:
            print("Response JSON:", response.json())
        except Exception:
            print("Response content:", response.text)

if __name__ == "__main__":
    # Replace with a valid ticket UUID from your database
    test_ticket_id = "00000000-0000-0000-0000-000000000000"
    test_ajax_update_status(test_ticket_id, "Resolved")
