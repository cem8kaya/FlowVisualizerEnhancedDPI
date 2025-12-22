
import os
import re

def get_files(directory, extensions):
    file_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(extensions):
                # Make relative to project root
                rel_path = os.path.relpath(os.path.join(root, file), start=".")
                file_list.append(rel_path)
    return file_list

def read_file(path):
    try:
        with open(path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return ""

def check_cmake_usage(file_path, cmake_content):
    # CMake matches are usually just the filename or relative path
    # complex regex to catch various ways files are added
    # But files are often added as "dir/file.cpp"
    # We'll just check if the basename is present if the full path isn't, 
    # but be careful about duplicates.
    # Safest is to check for the path relative to the CMakeLists.txt location.
    
    # src/CMakeLists.txt lists files relative to src/
    # tests/CMakeLists.txt lists files relative to tests/
    
    fname = os.path.basename(file_path)
    
    if file_path.startswith("src/"):
        rel_in_cmake = file_path[4:] # strip src/
        return rel_in_cmake in cmake_content
    elif file_path.startswith("tests/"):
        rel_in_cmake = file_path[6:] # strip tests/
        return rel_in_cmake in cmake_content
    
    return False

def check_header_usage(header_path, all_source_content):
    # Headers are included as "path/to/header.h" usually relative to include/
    if header_path.startswith("include/"):
        include_ref = header_path[8:] # strip include/
        return f'"{include_ref}"' in all_source_content or f'<{include_ref}>' in all_source_content
    return True # Assume used if not in include/ (shouldn't happen with our list)

def main():
    # 1. Analyze C++ Sources
    print("--- Unused C++ Source Files ---")
    src_files = get_files("src", (".cpp", ".c"))
    test_files = get_files("tests", (".cpp", ".c"))
    
    src_cmake = read_file("src/CMakeLists.txt")
    tests_cmake = read_file("tests/CMakeLists.txt")
    
    unused_src = []
    for f in src_files:
        if not check_cmake_usage(f, src_cmake):
            print(f)
            unused_src.append(f)
            
    print("\n--- Unused Test Files ---")
    unused_tests = []
    for f in test_files:
        if not check_cmake_usage(f, tests_cmake):
            print(f)
            unused_tests.append(f)

    # 2. Analyze Headers
    print("\n--- Unused Headers ---")
    header_files = get_files("include", (".h", ".hpp"))
    
    # Load all source content into memory (heavy but accurate'ish)
    all_content = ""
    for root, _, files in os.walk("."):
        if "build" in root or "node_modules" in root: continue
        for file in files:
            if file.endswith((".cpp", ".c", ".h", ".hpp")):
                with open(os.path.join(root, file), 'r', errors='ignore') as f:
                    all_content += f.read() + "\n"
    
    unused_headers = []
    for h in header_files:
        if not check_header_usage(h, all_content):
            print(h)
            unused_headers.append(h)
            
    # 3. Analyze Web Assets
    print("\n--- Unused Web Assets ---")
    ui_assets = get_files("ui/static", (".js", ".css"))
    
    # Load HTML content
    html_content = ""
    for root, _, files in os.walk("ui"):
        for file in files:
            if file.endswith(".html"):
                with open(os.path.join(root, file), 'r', errors='ignore') as f:
                    html_content += f.read() + "\n"
    
    unused_assets = []
    for asset in ui_assets:
        fname = os.path.basename(asset)
        if fname not in html_content:
             # double check if it's referenced in other JS files??
             # rudimentary check
             print(asset)
             unused_assets.append(asset)

if __name__ == "__main__":
    main()
