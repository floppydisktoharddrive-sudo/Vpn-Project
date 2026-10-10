import os


def simplify_and_indent_line(line, space_count=4):
    """Processes a single line to clean words and standardize indentation."""
    # 1. Expand existing tabs to spaces to read the layout uniformly
    expanded_line = line.expandtabs(space_count)

    if not expanded_line.strip():
        return ""

    # 2. Calculate the original indentation level (multiples of 4 spaces)
    leading_spaces = len(expanded_line) - len(expanded_line.lstrip(" "))
    indent_level = leading_spaces // space_count

    # 3. Flatten the text and force exactly 1 space between all internal words
    words = expanded_line.strip().split()
    clean_content = " ".join(words)

    # 4. Rebuild the line starting from the far left with perfect 4-space blocks
    return (" " * (indent_level * space_count)) + clean_content


def fix_file_line_by_line(file_path):
    """Reads a file line-by-line, flattens, cleans word spacing, and re-indents."""
    try:
        if not os.path.exists(file_path):
            print(f"Error: The file '{file_path}' does not exist.")
            return

        # Read original lines
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()

        # Clean and indent every line individually
        fixed_lines = []
        for line in lines:
            fixed_line = simplify_and_indent_line(line, space_count=4)
            # Maintain the original file break structure cleanly
            if line.endswith("\n") or line.endswith("\r\n"):
                fixed_lines.append(fixed_line + "\n")
            else:
                fixed_lines.append(fixed_line)

        # Overwrite target file with the simplified layout
        with open(file_path, "w", encoding="utf-8") as file:
            file.writelines(fixed_lines)

        print(f"Successfully cleaned word spaces and re-indented: {file_path}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    # This runs directly on your 'ai.py' target file
    target_file = "any_python_file_name.py"
    fix_file_line_by_line(target_file)
