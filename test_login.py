import requests
import re

session = requests.Session()
r_get = session.get("http://localhost:5000/login")
match = re.search(r'name="csrf-token"\s+content="([^"]+)"', r_get.text)
csrf_token = match.group(1) if match else "NOT_FOUND"

print(f"Got CSRF: {csrf_token}")
print(f"Cookies: {session.cookies.get_dict()}")

r_post = session.post(
    "http://localhost:5000/api/v1/auth/login",
    json={"username": "admin", "password": "Admin@WatchTower1!"},
    headers={"X-CSRFToken": csrf_token}
)
print(f"Status: {r_post.status_code}")
print(f"Response: {r_post.text}")

