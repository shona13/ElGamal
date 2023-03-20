import timeit
import gmpy2 as gmp

'''
    Author : Sonal Joshi
    Description : ElGamal scheme implementation using gmpy2 library
'''


# Randomly generates secret key x, message m and r for 128 bit security level
def random_num():
    random_state = gmp.random_state(hash(gmp.random_state()))

    # Randomly generates x
    x = gmp.mpz_urandomb(random_state, gmp.mpz('3072'))

    # Randomly generates message m
    m = gmp.mpz_urandomb(random_state, gmp.mpz('3072'))
    # Checking for gcd of (m,p) = 1 i.e Check if r belongs to Zn*
    while gmp.gcd(m, p) != gmp.mpz(1):
        m = gmp.mpz_urandomb(random_state, gmp.mpz('3072'))

    # Randomly generating number r
    r = gmp.mpz_urandomb(random_state, gmp.mpz('3072'))
    # Checking for gcd of (r,p) = 1 i.e if r belongs to Zn*
    while gmp.gcd(r, p) != gmp.mpz(1):
        r = gmp.mpz_urandomb(random_state, gmp.mpz('3072'))
    return x,m,r


# Key generation - Takes parameters prime p, generator g and x
def key_gen(p,g,x):
    y = gmp.powmod(g,x,p)
    return y


# Encryption function - Takes parameters  prime p, generator g and message m
def encrypt(p,g,m):
    # Ciphertext c1 & c2 generation
    c1 = gmp.powmod(g,r,p)
    c2 = gmp.mod(m*gmp.powmod(y,r,p),p)
    # Ciphertext C = (c1,c2)
    C = (c1, c2)
    return C


# Decryption function - Takes parameters Prime p, randomly generated secret key x & ciphertext C = c1,c2
def decrypt(p,x,C):
    # Unpacking tuple c
    c1, c2 = C
    # - x is for inverse
    t = gmp.powmod(c1,-x,p)
    # Calculates decrypted message m as m1
    m1 = gmp.mod(c2*t,p)
    return m1


if __name__ == '__main__':  #Main function
    # generator (given)
    g = gmp.mpz(2)
    # Prime p (given)
    p = gmp.mpz(5809605995369958062791915965639201402176612226902900533702900882779736177890990861472094774477339581147373410185646378328043729800750470098210924487866935059164371588168047540943981644516632755067501626434556398193186628990071248660819361205119793693985433297036118232914410171876807536457391277857011849897410207519105333355801121109356897459426271845471397952675959440793493071628394122780510124618488232602464649876850458861245784240929258426287699705312584509625419513463605155428017165714465363094021609290561084025893662561222573202082865797821865270991145082200656978177192827024538990239969175546190770645685893438011714430426409338676314743571154537142031573004276428701433036381801705308659830751190352946025482059931306571004727362479688415574702596946457770284148435989129632853918392117997472632693078113129886487399347796982772784615865232621289656944284216824611318709764535152507354116344703769998514148343807)

    # Calling all the functions by creating objects
    x,m,r = random_num()
    y = key_gen(p, g, x)
    cipher = encrypt(p,g,m)
    m1 = decrypt(p,x,cipher)

    '''
        Printing values on terminal
    '''

    ### Key Generation ###
    print("-"*20, "Key generation", "-"*20)
    print(f"\nThe first prime is p = {p} \nThe value of g = {g}")
    print(f"Public key is x (y,g,p) = ({y},{g},{p}) \nPrivate Key is x  = {x}\n\n")

    ### Encryption process ###
    print("-"*20, "Encryption", "-"*20)
    print(f"\nPlaintext  (randomly generated) is m = {m} \nThe random number is r = {r} \nCiphertext is c = {cipher[0]},{cipher[1]}\n\n")

    ### Decryption process ###
    print("-" * 20, "Decryption", "-" * 20)
    print(f"\nCiphertext to be decrypted c = ({cipher[0]},{cipher[1]}) \nDecrypted plaintext is m = {m}")

    ### Time taken to execute the program ###
    print("\nTime taken to run (seconds): ", timeit.timeit())

