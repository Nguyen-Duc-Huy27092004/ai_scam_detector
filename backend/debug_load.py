import sys
try:
    import main
    print("MAIN LOADED SUCCESSFULLY")
except Exception as e:
    import traceback
    print("ERROR LOADING MAIN:")
    traceback.print_exc()
print("SYS PATH:")
print(sys.path)
