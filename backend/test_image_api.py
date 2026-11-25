import requests

url = "http://127.0.0.1:5000/analyze-image"

with open("test_image.jpg", "rb") as image:
    response = requests.post(
        url,
        files={"image": image}
    )

print("API STATUS:", response.status_code)
print("API RESULT:", response.json())