import hashlib

def append_table(file, out, alg, lines):
	for i in range(lines):
		password = file.readline().rstrip("\r\n").encode(encoding="utf-8")
		alg.update(password)
		digest = alg.hexdigest()

		out.write(digest + "," + password.decode("utf-8") + "," + alg.name + "\n")

def main():
	file_str = input("Password List=")
	out_str = input("Output File=")	
	alg_str = input("Hash Algorithm=")
	lines = int(input("Lines="))
	append = input("Overwrite file (y/n)? ").lower()

	if (append == 'y'):
		append = False
	elif (append == 'n'): #Default will be to not overwrite file
		append = True
	else:
		print("Input '" + str(append) + "' invalid: Appending file by default.`")
		append = True

	h = hashlib.new(alg_str)
	
	f = open(file_str, 'r')
 
	o = open(out_str, 'a' if append else 'w')

	append_table(f, o, h, lines) 

main()
