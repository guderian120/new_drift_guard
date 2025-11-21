import os
try:
    with open("test_python_output.txt", "w") as f:
        f.write("Python is working\n")
        f.write(f"CWD: {os.getcwd()}")
    print("Script executed successfully")
except Exception as e:
    print(f"Error: {e}")
