

my_string = "example.txt"

if ".txt" in my_string:
    print("String contains '.txt'")
else:
    print("String does not contain '.txt'")




filetype = "image/png"
file_subtype = filetype.split('/')[1]
print(file_subtype)
