import json
import os

notebook_path = "c:\\Users\\RIYANSHI\\OneDrive\\Source code\\intellphish backend\\intellphish.ipynb"

with open(notebook_path, 'r', encoding='utf-8') as f:
    nb = json.load(f)

changed_count = 0

for cell in nb.get('cells', []):
    if cell.get('cell_type') == 'code':
        new_source = []
        for line in cell.get('source', []):
            orig_line = line
            
            line = line.replace("train_test_split(X, y,", "train_test_split(features, df.Label,")
            line = line.replace("train_test_split(feature, df.Label)", "train_test_split(features, df.Label)")
            
            line = line.replace("1_model.predict", "model_1.predict")
            
            if "fx29id1.txt'\n" in line:
                line = line.replace("fx29id1.txt'\n", "fx29id1.txt']\n")
            elif "fx29id1.txt'" in line and not "fx29id1.txt']" in line:
                line = line.replace("fx29id1.txt'", "fx29id1.txt']")
                
            if "technology.html'\n" in line:
                line = line.replace("technology.html'\n", "technology.html']\n")
            elif "technology.html'" in line and not "technology.html']" in line:
                line = line.replace("technology.html'", "technology.html']")
                
            line = line.replace(")N I", "))")
            line = line.replace("figsize= (6,4))[\n", "figsize= (6,4))\n")
            
            if orig_line != line:
                changed_count += 1
                
            new_source.append(line)
        cell['source'] = new_source

with open(notebook_path, 'w', encoding='utf-8') as f:
    json.dump(nb, f, indent=1)

print(f"Fixed {changed_count} errors in the notebook.")
