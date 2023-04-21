src = r'C:\Users\33761\Desktop\M1\s2\rout\projet'

def get_all_files_from_folder(src_folder):
  '''Reconstructs the architecture of the src folder, but in the executable version
  '''
  l = []
  for root, dirs, files in os.walk(src_folder):
    for file in files:
      l.append((os.path.join(root,file), root[len(src):]))
  return l

bin = get_all_files_from_folder(src)