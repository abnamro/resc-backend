import os

print("-----")
for key, value in os.environ.items():
    print(f"{key}: {value}")
print("-----")
