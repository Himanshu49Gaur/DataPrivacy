import os

def generate_tree(startpath: str) -> str:
    """Generates a hierarchical ASCII tree of the project directory.

    Args:
        startpath: The root directory to start the scan from.

    Returns:
        A formatted string representing the directory tree.
    """
    output = []
    ignore_dirs = {
        '__pycache__', '.git', 'venv', 'env', '.venv', '.pytest_cache', '.gemini'
    }

    for root, dirs, files in os.walk(startpath):
        # Filter directories in-place
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        level = root.replace(startpath, '').count(os.sep)
        indent = '│   ' * (level)
        folder_name = os.path.basename(root)
        
        if root == startpath:
            output.append('.')
        else:
            output.append(f'{indent[:-4]}├── {folder_name}/')

        sub_indent = '│   ' * (level + 1)
        for f in files:
            output.append(f'{sub_indent[:-4]}└── {f}')

    return '\n'.join(output)

if __name__ == "__main__":
    # Define root path (current directory)
    root_dir = os.getcwd()
    
    # Generate tree
    tree_string = generate_tree(root_dir)
    
    # Write to file
    with open('project_structure.txt', 'w', encoding='utf-8') as f:
        f.write(tree_string)
    
    # Print to console
    print(tree_string)
