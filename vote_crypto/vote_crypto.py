from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os
import os.path



###########
### API ###
###########



def sign( signing_key, ciphertext: str ) -> str:

    try:
        signature = signing_key.sign( bytes.fromhex( ciphertext ),
                                      padding.PSS(
                                          mgf = padding.MGF1( hashes.SHA256() ),
                                          salt_length = padding.PSS.MAX_LENGTH
                                      ),
                                      hashes.SHA256() )
    except:
        raise Exception( 'Unable to sign message due to internal cryptographic error' )

    return signature.hex()



def verify( verification_key, ciphertext: str, signature: str ) -> ( bool, str ):

    try:
        verification_key.verify( bytes.fromhex( signature ),
                                 bytes.fromhex( ciphertext ),
                                 padding.PSS(
                                     mgf = padding.MGF1( hashes.SHA256() ),
                                     salt_length = padding.PSS.MAX_LENGTH
                                 ),
                                 hashes.SHA256() )
    except InvalidSignature:
        return ( False, None )
    except:
        raise Exception( 'Unable to verify message due to internal cryptographic error' )


    return ( True, ciphertext )



def encrypt( encryption_key, identifier: str, candidate: str, token: str ) -> str:

    message = '{}||{}||{}'.format( identifier, candidate, token )

    try:
        ciphertext = encryption_key.encrypt( str.encode( message ),
                                             padding.OAEP(
                                                 mgf = padding.MGF1( hashes.SHA256() ),
                                                 algorithm = hashes.SHA256(),
                                                 label = None
                                             ) )
    except:
        raise Exception( 'Unable to encrypt message due to internal cryptographic error' )

    return ciphertext.hex()



def decrypt( decryption_key, ciphertext: str ) -> ( str, str, str ):

    try:
        plaintext = decryption_key.decrypt( bytes.fromhex( ciphertext ),
                                            padding.OAEP(
                                                mgf = padding.MGF1( hashes.SHA256() ),
                                                algorithm = hashes.SHA256(),
                                                label = None
                                            ) )
    except:
        raise Exception( 'Unable to decrypt message due to internal cryptographic error' )

    ( voter_id, candidate, token ) = bytes.decode( plaintext ).split( '||' )

    return ( voter_id, candidate, token )



def encode( ciphertext: str, signature: str ) -> str:
    return '{}||{}'.format( ciphertext, signature )



def decode( payload: str ) -> ( str, str ):
    return tuple( payload.split('||') )



############
### Keys ###
############



keyfiles = [ '.c1', '.c2', '.ser' ]
c1       = None
c2       = None
ser      = None
found    = False
for folder in os.walk( '.' ) :
    path, _, files = folder

    if keyfiles[ 0 ] in files and keyfiles[ 1 ] in files and keyfiles[ 2 ] in files:
        found = True
        c1    = open( os.path.join( path, keyfiles[ 0 ] ), 'r' )
        c2    = open( os.path.join( path, keyfiles[ 1 ] ), 'r' )
        ser   = open( os.path.join( path, keyfiles[ 2 ] ), 'r' )
        break


if not found:

    c1 = rsa.generate_private_key( public_exponent = 65537, key_size = 4096, backend = default_backend() )
    client1 = {
        'private_key' : c1,
        'public_key'  : c1.public_key()
    }

    with open( '.c1', 'w' ) as fp:
        pem = c1.private_bytes(
            encoding = serialization.Encoding.PEM,
            format   = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        )

        fp.write( pem.decode( 'ascii' ) )
        fp.close()


    c2 = rsa.generate_private_key( public_exponent = 65537, key_size = 4096, backend = default_backend() )
    client2 = {
        'private_key' : c2,
        'public_key'  : c2.public_key()
    }

    with open( '.c2', 'w' ) as fp:
        pem = c2.private_bytes(
            encoding = serialization.Encoding.PEM,
            format   = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        )

        fp.write( pem.decode( 'ascii' ) )
        fp.close()


    ser = rsa.generate_private_key( public_exponent = 65537, key_size = 4096, backend = default_backend() )
    server = {
        'private_key' : ser,
        'public_key'  : ser.public_key()
    }

    with open( '.ser', 'w' ) as fp:
        pem = ser.private_bytes(
            encoding = serialization.Encoding.PEM,
            format   = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        )

        fp.write( pem.decode( 'ascii' ) )
        fp.close()


else:


    pem = c1.read().encode()
    c1.close()

    c1 = serialization.load_pem_private_key( pem, backend = default_backend(), password = None )
    client1 = {
        'private_key' : c1,
        'public_key'  : c1.public_key()
    }


    pem = c2.read().encode()
    c2.close()

    c2 = serialization.load_pem_private_key( pem, backend = default_backend(), password = None )
    client2 = {
        'private_key' : c2,
        'public_key'  : c2.public_key()
    }


    pem = ser.read().encode()
    ser.close()

    ser = serialization.load_pem_private_key( pem, backend = default_backend(), password = None )
    server = {
        'private_key' : ser,
        'public_key'  : ser.public_key()
    }
