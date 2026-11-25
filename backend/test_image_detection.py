from services.image_detector import detect_image

result = detect_image("test_image.jpg")

print("\nIMAGE DETECTION RESULT")
print("----------------------")
print(result)