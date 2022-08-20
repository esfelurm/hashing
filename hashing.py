import os
os.system("pip install termcolor")
os.system("pip install pyfiglet")
import codecs, time, binascii, re, sys, hashlib, pyfiglet, marshal
from base64 import b64encode, b64decode
from termcolor import colored
#end importing
rd, gn, lgn, yw, lrd, be, pe = '\033[00;31m', '\033[00;32m', '\033[01;32m', '\033[01;33m', '\033[01;31m', '\033[00;34m', '\033[01;35m'
cn = '\033[00;36m'

def clear_():
    os.system("clear")
hash_md5 = colored(pyfiglet.figlet_format('MD5', font = 'banner3-D'), 'green')
hash_Sha1 = colored(pyfiglet.figlet_format('Sha1', font = 'banner3-D'), 'green')
hash_Sha224 = colored(pyfiglet.figlet_format('Sha224', font = 'banner3-D'), 'green')
hash_Sha256 = colored(pyfiglet.figlet_format('Sha256', font = 'banner3-D'), 'green')
hash_sha384 = colored(pyfiglet.figlet_format('sha384', font = 'banner3-D'), 'green')
hash_sha512 = colored(pyfiglet.figlet_format('sha512', font = 'banner3-D'), 'green')
hash_Marshal = colored(pyfiglet.figlet_format('Marshal', font = 'banner3-D'), 'green')
hash_base64 = colored(pyfiglet.figlet_format('Base64', font = 'banner3-D'), 'green')
hash_binario = colored(pyfiglet.figlet_format('Binario', font = 'banner3-D'), 'green')
hash_hexadecimal = colored(pyfiglet.figlet_format('Hexadecimal', font = 'banner3-D'), 'green')
hash_cifraDeCesar = colored(pyfiglet.figlet_format('CifraDeCesar', font = 'banner3-D'), 'green')
#____________________________________
def Again(frase, call):
	Number = input(frase)
	if Number == "y" or Number == "Y":
		call()
	elif Number == "n" or Number == "N":
		esfelurm()
	else:
		Again(frase,call)
def esfelurm():
	clear_()
	print (f"""
	          {lrd}Version :{gn} 3.0.1

                    {lrd}↟encryption↟

{lgn}Md5 {yw}={rd}❯❯❯{lrd} [1]{gn}❯ {be}| {lgn}Sha224 {yw}={rd}❯❯❯{lrd} [3]{gn}❯ {be}| {lgn}Sha384 {yw}={rd}❯❯❯ {lrd}[5]{gn}❯ {be}|

{pe}_____________________________________________________

{lgn}Sha1 {yw}={rd}❯❯❯ {lrd}[2]{gn}❯{be} | {lgn}Sha256 {yw}={rd}❯❯❯{lrd} [4]❯ {be}| {lgn}Sha512 {yw}={rd}❯❯❯{lrd}  [6]{gn}❯ {be}|

                
                {lgn}Marshal {yw}={rd}❯❯❯ {lrd}[7]{gn}❯{be} |

{pe}_____________________________________________________

         {lrd}↟encryption    {lgn}and     {lrd} decryption↟

{lgn}Base64 {yw}={rd}❯❯❯ {lrd}[A]{gn}❯ {be}|                {lgn}Binario {yw}={rd}❯❯❯ {lrd}[B]{gn}❯ {be}|

{cn}_____________________________________________________

{lgn}Hexadecimal {yw}={rd}❯❯❯ {lrd}[H]{gn}❯ {be}|      {lgn}CifraDeCesar {yw}={rd}❯❯❯ {lrd}[C]{gn}❯ {be}|

                     {lrd}[E] {lgn}Exit
           
           {lgn}channel {yw}Telegram {lrd}: {pe}@{cn}esfelurm

{cn}_____________________________________________________

""")
	Number = input(f"""{lrd}┌─<({cn}hash{gn}@esfelurm{lrd})-{yw}[~]{lrd}>
└─< ({gn}main{lrd}){pe}* {lrd}>──»  {cn}""")
	if Number == "1":
		Md5()
	elif Number == "2":
		Sha1()
	elif Number == "3":
		Sha224()
	elif Number == "4":
		Sha256()
	elif Number == "5":
		Sha384()
	elif Number == "6":
		Sha512()
	elif Number == "7":
		Marshal()
	elif Number == "A" or Number == "a":
		Base64()
	elif Number == "B" or Number == "b":
		Binario()
	elif Number == "H" or Number == "h":
		Hexadecimal()
	elif Number == "C" or Number == "c":
		CifraDeCesar()
	elif Number == "E" or Number == "e":
		print (f"{lrd}Exit Bye Bye")
		exit(1)
	else:
		esfelurm()
def Md5():
	clear_()
	print (hash_md5)
	result = colored(pyfiglet.figlet_format('encode MD5', font = 'banner3-D'), 'green')
	sstring = input(f"{rd}[+]{lgn} TEXT ENCRYPT  {lrd}MD5 {yw}=>>{gn} ")
	hashing = hashlib.md5(sstring.encode())
	print("")
	print(f"{lrd}[!] {lgn}text : {lrd}", hashing.hexdigest())
	print("")
	Again(f"{rd}[!]{gn} do you continue {lrd}(y/n) {yw}=>> {gn}", Md5)
def Sha1():
	clear_()
	print (hash_Sha1)
	sstring = input(f"{rd}[+] {gn}TEXT ENCRYPT {lrd}SHA1 {yw}=>>{gn} ")
	hashing = hashlib.sha1(sstring.encode())
	print("")
	print(f"{lrd}[!] {lgn}text : {lrd}",hashing.hexdigest())
	print("")
	Again(f"{rd}[!]{gn} do you continue {lrd}(y/n) {yw}=>> {gn}", Sha1)
def Sha224():
	clear_()
	print (hash_Sha224)
	sstring = input(f"{rd}[+] {gn}TEXT ENCRYPT {lrd}SHA224 {yw}=>>{gn} ")
	hashing = hashlib.sha224(sstring.encode())
	print("")
	print(f"{lrd}[!] {lgn}text : {lrd}",hashing.hexdigest())
	print("")
	Again(f"{rd}[!]{gn} do you continue {lrd}(y/n) {yw}=>> {gn}", Sha224)
def Sha256():
	clear_()
	print (hash_Sha256)
	sstring = input(f"{rd}[+] {gn}TEXT ENCRYPT {lrd}SHA256 {yw}=>> {gn}")
	hashing = hashlib.sha256(sstring.encode())
	print("")
	print(f"{lrd}[!] {lgn}text : {lrd}",hashing.hexdigest())
	print("")
	Again(f"{rd}[!]{gn} do you continue {lrd}(y/n) {yw}=>> {gn}", Sha256)
def Sha384():
	clear_()
	print (hash_sha384)
	sstring = input(f"{rd}[+] {gn}TEXT ENCRYPT {lrd}SHA384 {yw}=>> {gn}")
	hashing = hashlib.sha384(sstring.encode())
	print("")
	print(f"{lrd}[!] {lgn}text : {lrd}",hashing.hexdigest())
	print("")
	Again(f"{rd}[!]{gn} do you continue {lrd}(y/n) {yw}=>> {gn}", Sha384)
def Sha512():
	clear_()
	print (hash_sha512)
	sstring = input(f"{rd}[+] {gn}TEXT ENCRYPT {lrd}SHA512{yw} =>> {gn}")
	hashing = hashlib.sha512(sstring.encode())
	print("")
	print(f"{lrd}[!] {lgn}text : {lrd}",hashing.hexdigest())
	print("")
	Again(f"{rd}[!]{gn} do you continue {lrd}(y/n) {yw}=>> {gn}", Sha512)
def Base64_():
	clear_()
	print (hash_base64)
	sstring = str(input(f"{rd}[+] {gn}TEXT TRANSFORM {lrd}BASE64{yw} =>> {gn}")) 
	print("")
	encode = b64encode(sstring.encode('utf-8')) 
	decode = encode.decode('utf-8')
	print(f"{lrd}[!] {lgn}text : {lrd}",decode)
	print("") 
	Again(f"{rd}[!]{gn} do you continue {lrd}(y/n) {yw}=>> {gn}", Base64_)
def Base64D():
	clear_()
	print (hash_base64)
	sstring = str(input(f"{rd}[+] {gn}TEXT {pe}UNCOVER {lrd}BASE64 {yw}=>> {gn}")) 
	print("")
	try:
		decode = b64decode(sstring).decode('utf-8')
		print(decode)
		print("{lrd}")
	except:
		print(f"{lrd}Is wrong ! ")
		time.sleep(3)
		Base64D() 
	Again(f"{rd}[!]{gn} do you continue {lrd}(y/n) {yw}=>> {gn}", Base64D)
def Base64():
	clear_()
	print(f"""
{rd}[-] {cn}Which option : 
{pe}______________________
{rd}[1] {gn}ENCODE 

{rd}[2] {lrd}DECODE 
""")
	Number = input(f"{rd}[*] {gn}Number {yw}=>> {lrd}")
	if Number == "1":
		Base64_()
	elif Number == "2":
		Base64D()
	else:
		Base64()
def BinarioE(encoding='utf-8', errors='surrogatepass'):
	clear_()
	try:
		sstring = input(f"{rd}[+] {gn}TEXT TRANSFORM {lrd}BINARIO {yw}=>>{gn} ")
		print("")
		bits = bin(int(binascii.hexlify(sstring.encode(encoding, errors)), 16))[2:]
		print(f"{lrd}[!] {lgn}text : {lrd}",bits.zfill(8 * ((len(bits) + 7) // 8)))
		print("")
	except:
		print(f"{rd}[!]{lrd} ERROR")
		time.sleep(3)
		Binario()
	Again(f"{rd}[!]{gn} do you continue {lrd}(y/n) {yw}=>> {gn}", Binario)
def BinarioD(encoding='utf-8', errors='surrogatepass'):
	clear_()
	try:
		binario = input(f"{rd}[+] {gn}TEXT {pe}UNCOVER {lrd}BINARY {yw}=>>{gn} ")
		binario = binario.replace(" ", "")
		n = int(binario, 2)
		print("")
		print(f"{lrd}[!] {lgn}text : {lrd}",int2bytes(n).decode(encoding, errors))
		print("")
	except:
		print(f"{rd}[!]{lrd} ERROR")
		time.sleep(3)
		BinarioD()
	Again(f"{rd}[!]{gn} do you continue  {lrd}(y/n) {yw}=>> {gn}", BinarioD)
def int2bytes(i):
	hex_string = '%x' % i
	n = len(hex_string)
	return binascii.unhexlify(hex_string.zfill(n + (n & 1)))
def Binario():
	clear_()
	print (hash_binario)
	print(f"""
{rd}[-] {cn}Which option : 
{pe}______________________
{rd}[1] {gn}ENCODE 

{rd}[2] {lrd}DECODE 
""")
	Number = input(f"{rd}[*] {gn}Number {yw}=>> {lrd}")
	if Number == "1":
		BinarioE()
	elif Number == "2":
		BinarioD()
	else:
		Binario()
def Hexa():
	clear_()
	print (hash_hexadecimal)
	sstring = input(f"{rd}[+] {gn}TEXT TRANSFORM {lrd}HEXADECIMAL {yw}=>> {gn}")
	print("")
	encode = binascii.hexlify(bytes(sstring, "utf-8"))
	encode = str(encode).strip("b")
	encode = encode.strip("'")
	encode = re.sub(r'(..)', r'\1 ', encode).strip()
	print(f"{lrd}[!] {lgn}text : {lrd}",encode)
	print("")
	Again(f"{rd}[!]{gn} do you continue {lrd}(y/{gn}/n) {yw}=>> {gn}", Hexa)
def HexaD():
	clear_()
	try:
		sstring = input(f"{rd}[+] {gn}TEXT {pe}UNCOVER {lrd}HEXADECIMAL {yw}=>> {gn}")
		print(f"{lrd}")
		decode = bytes.fromhex(sstring).decode('utf-8')
		print(f"{lrd}[!] {lgn}text : {lrd}",decode)
		print("")
	except:
		print(f"{rd}[!]{lrd} ERROR")
		time.sleep(3)
		HexaD()
	Again(f"{rd}[!]{gn} do you continue {lrd}(y/n) {yw}=>> {gn}", HexaD)
def Hexadecimal():
	clear_()
	print(f"""
{rd}[-] {cn}Which option : 
{pe}______________________
{rd}[1] {gn}ENCODE 

{rd}[2] {lrd}DECODE 
""")
	Number = input(f"{rd}[*] {gn}Number {yw}=>> {lrd}")
	if Number == "1":
		Hexa()
	elif Number == "2":
		HexaD()
	else:
		Hexadecimal()
def CifraDeCesar():
	clear_()
	print (hash_cifraDeCesar)
	print(f"""
{rd}[-] {cn}Which option : 
{pe}______________________
{rd}[1] {gn}ENCODE 

{rd}[2] {lrd}DECODE 
""")
	Number = input(f"{rd}[*] {gn}Number {yw}=>> {lrd}")
	if Number == "1":
		ChamarBloco1()
	elif Number == "2":
		ChamarBloco2()
	else:
		CifraDeCesar()
def cifrar(palavras, chave):
	abc = "abcdefghijklmnopqrstuvwxyz "
	text_cifrado = ''

	for letra in palavras:
		soma = abc.find(letra) + chave
		modulo = int(soma) % len(abc)
		text_cifrado = text_cifrado + str(abc[modulo])

	return text_cifrado
def decifrar(palavras, chave):
	abc = "abcdefghijklmnopqrstuvwxyz "
	text_cifrado = ''

	for letra in palavras:
		soma = abc.find(letra) - chave
		modulo = int(soma) % len(abc)
		text_cifrado = text_cifrado + str(abc[modulo])

	return text_cifrado
def ChamarBloco1():
	clear_()
	try:
		EN = str(input(f'{rd}[-] {gn}TEXT {pe}CIPHER {yw}=>> {gn}')).lower()
		ND = int(input(f'{rd}[!] {gn}NUMERICAL {lrd}KEY {yw}=>> {gn}'))
		print(f"{rd}[~] {yw}Answer : {gn}", cifrar(EN, ND))
		print("")
	except:
		print(f"{rd}[!]{lrd} ERROR")
		time.sleep(3)
		ChamarBloco1()
	Again(f"{rd}[!]{gn} do you continue {lrd}(y/{gn}/n) {yw}=>> {gn}", ChamarBloco1)
def ChamarBloco2():
	clear_()
	try:
		en = str(input(f'{rd}[+] {gn}TEXT {pe}DECODE')).lower()
		ne = int(input(f'{rd}[!] {gn}NUMERICAL {lrd}KEY {yw}=>>  {gn}'))
		print(f"{rd}[~] {yw}Answer :{gn}", decifrar(en, ne))
		print("")
	except:
		print(f"{rd}[!]{lrd} ERROR")
		time.sleep(3)
		ChamarBloco2()
	Again(f"{rd}[!]{gn} do you continue  {lrd}(y/{gn}/n) {yw}=>> {gn}", ChamarBloco2)
def Marshal():
    clear_()
    print (hash_Marshal)
    sstring = input(f"{rd}[+]{lgn} TEXT ENCRYPT  {lrd}MARSHAL {yw}=>>{gn} ")
    hashing = marshal.dumps(sstring)
    encode = str(hashing).strip("b")
    hashing = encode.strip("'")
    encode = re.sub(r'(..)', r'\1 ', hashing)
    print("")
    print (f"{lrd}[!] {lgn}text : {lrd}",hashing)
    print ("")
    Again(f"{rd}[!]{gn} do you continue  {lrd}(y/n) {yw}=>> {gn}", Marshal)
esfelurm()
