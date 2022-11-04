import argparse
import base64
import hashlib
import json
import uuid
import warnings
from datetime import datetime, timedelta
 
import OpenSSL
import boto3
import jks
import jwt
import requests
from botocore.exceptions import ClientError
 
ARG_DESC_JKS = 'Required (if X.509 Certificate or PKCS12 file not provided). Java Key Store (JKS) file location.\n' \
                'examples: ./my_file.jks or ../../my_file.jks or I:/tom/x509_folder/my_file.jks'
 
ARG_DESC_PKCS12 = 'Required (if X.509 Certificate or JKS file not provided). PKCS12 file location.\n' \
                'examples: ./my_file.p12 or ../../my_file.p12 or I:/tom/x509_folder/my_file.p12'
 
ARG_DESC_PASS_PHRASE = 'Required (only for JKS or PKCS12). Java Key Store (JKS) pass phrase'
 
ARG_DESC_AWS_SECRET_NAME = 'Required (only for JKS or PKCS12). AWS Secret Name for the Java Key Store (JKS) pass phrase'
 
ARG_DESC_AWS_REGION = 'Required (only for AWS Secret Name). AWS Region. (default: us-east-1)'
 
ARG_DESC_AWS_PROFILE = 'Required (only for AWS Secret Name). AWS profile. (default: adfs)'
 
ARG_DESC_AWS_SECRET_NAME = 'Required (only for AWS Secret Name). AWS Secret Key Name against which the password is stored.'
 
ARG_DESC_X509_CERT = 'Required (if JKS or PKCS12 not provided). X509 Certificate.'
 
ARG_DESC_PRIVATE_KEY = 'Required (if JKS or PKCS12 not provided). Private Key.'
 
ARG_DESC_CLIENT_ID = 'Required. IDA X.509 Client ID.\n' \
                        'examples: CC-106514-V227448-89643-DEV'
 
ARG_DESC_RESOURCE_ID = 'Required. IDA Target Resource ID.\n' \
                        'examples: JPMC:URI:RS-109635-78346-TARGETSYSTEM-DEV'
 
ARG_DESC_KEY_ALIAS = 'Required. Key alias used while creating JKS file.' \
                    'If unclear, refer to your openssl or keytool command used to create the JKS file.'
 
ARG_DESC_ENV = 'Required. IDA token URL is going to be set using this ENV value.\n' \
                    'example: dev -> https://idadg2.jpmorganchase.com/adfs/oauth2/token/\n' \
                    'example: uat -> https://idauatg2.jpmorganchase.com/adfs/oauth2/token/\n' \
                    'example: prod -> https://idag2.jpmorganchase.com/adfs/oauth2/token/'
 
ARG_DESC_VERBOSE = 'Optional. Print verbose logs, if required.\n' \
                    'examples: -v True or --verbose True'
 
 
_ASN1 = OpenSSL.crypto.FILETYPE_ASN1
_PEM = OpenSSL.crypto.FILETYPE_PEM
 
 
def main(parsed_args):
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    verbose = True if parsed_args.verbose else False
 
    pass_phrase = get_jks_pass_phrase(parsed_args)
    if verbose:
        print("pass_phrase: ", pass_phrase, end='\n')
 
    if parsed_args.jks:
        context = get_ssl_context_from_jks(parsed_args.jks, pass_phrase, parsed_args.alias)
    elif parsed_args.pkcs12:
        context = get_ssl_context_from_pkcs12(parsed_args.pkcs12, pass_phrase)
    else:
        context = get_ssl_context_from_x509_cert(parsed_args.x509_cert, parsed_args.private_key)
 
    token_url = get_ida_token_url(parsed_args.env)
 
    if verbose:
        print("Creating JWT Header...", end='\n')
    jwt_header = create_jwt_header(context.get('certificate'))
    if verbose:
        print("jwt_header: ", jwt_header, end='\n')
 
    if verbose:
        print("Creating JWT Claims...", end='\n')
    jwt_claims = create_jwt_claims(parsed_args, token_url)
    if verbose:
        print("jwt_claims: ", jwt_claims, end='\n')
 
    if verbose:
        print("Creating Signed JWT Request...", end='\n')
    jwt_signed_request = create_jwt_signed_request(jwt_claims, jwt_header, context.get('private_key'))
    if verbose:
        print("jwt_signed_request: ", jwt_signed_request, end='\n')
 
    if verbose:
        print("Verifying the Signed JWT Request...", end='\n')
    decoded_jwt_signed_request = verify_jwt_signed_request(jwt_signed_request, context.get('public_key'))
    if verbose:
        print("decoded_jwt_signed_request: ", decoded_jwt_signed_request, end='\n')
 
    if verbose:
        print("Creating JWT Payload...", end='\n')
    jwt_payload = create_jwt_payload(jwt_signed_request, parsed_args)
    if verbose:
        print("jwt_payload: ", jwt_payload, end='\n')
 
    if verbose:
        print("Getting IDA Token...", end='\n')
    ida_token = get_ida_token(jwt_payload, token_url)
    print(ida_token.text, end='\n')
 
 
def get_jks_pass_phrase(parsed_args):
    if parsed_args.pass_phrase:
        return parsed_args.pass_phrase
    else:
        return get_aws_secret(parsed_args)
 
 
def get_aws_secret(parsed_args):
    secret_name = parsed_args.aws_secret_name
    region_name = parsed_args.aws_region
 
    # Create a Secrets Manager client
    session = boto3.session.Session(profile_name=parsed_args.aws_profile)
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
 
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if parsed_args.verbose:
            print("aws_response: ", get_secret_value_response, end='\n')
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            if parsed_args.verbose:
                print("aws_secret from aws_response: ", secret, end='\n')
 
            # Convert String to JSON
            secret = json.loads(secret)
            if parsed_args.aws_secret_key_name in secret:
                aws_secret_value = secret[parsed_args.aws_secret_key_name]
                if parsed_args.verbose:
                    print("aws_secret_value: ", aws_secret_value, end='\n')
                return aws_secret_value
            else:
                print("No aws secret value found.", end='\n')
                return None
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            return decoded_binary_secret
 
 
def create_jwt_header(certificate):
    kid = hashlib.sha1(certificate).hexdigest().upper()
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": kid
    }
    return header
 
 
def create_jwt_claims(parsed_args, token_url):
    time_now = datetime.now()
    time_exp = time_now + timedelta(days=2)
 
    iss = parsed_args.client_id
    aud = token_url
    sub = parsed_args.client_id
    exp = int(time_exp.timestamp())
    iat = int(time_now.timestamp())
    jti = str(uuid.uuid4())
 
    claims = {
        "iss": iss,
        "sub": sub,
        "aud": aud,
        "jti": jti,
        "exp": exp,
        "iat": iat
    }
    return claims
 
 
def create_jwt_signed_request(jwt_claims, jwt_header, private_key):
    signed_jwt_request = jwt.encode(jwt_claims, private_key, algorithm='RS256', headers=jwt_header)
    return signed_jwt_request
 
 
def verify_jwt_signed_request(jwt_signed_request, public_key):
    jwt_options = {
        'verify_signature': True,
        'verify_exp': True,
        'verify_nbf': False,
        'verify_iat': True,
        'verify_aud': False
    }
 
    decoded_jwt_signed_request = jwt.decode(jwt_signed_request, public_key, algorithms='RS256', options=jwt_options)
    return decoded_jwt_signed_request
 
 
def create_jwt_payload(jwt_signed_request, parsed_args):
    grant_type = str('urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
    payload = 'client_id=' + parsed_args.client_id
    payload += '&client_assertion_type=' + grant_type
    payload += '&client_assertion=' + jwt_signed_request
    payload += '&grant_type=client_credentials'
    payload += '&resource=' + parsed_args.resource_id
    return payload
 
 
def get_ida_token_url(env):
    env = env.lower()
    if env == "dev":
        token_url = "https://idadg2.jpmorganchase.com/adfs/oauth2/token/"
    elif env == "uat":
        token_url = "https://idauatg2.jpmorganchase.com/adfs/oauth2/token/"
    else:
        token_url = "https://idag2.jpmorganchase.com/adfs/oauth2/token/"
 
    return token_url
 
 
def get_ida_token(jwt_payload, token_url):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
 
    token = requests.post(token_url, data=jwt_payload, headers=headers)
    return token
 
 
def get_ssl_context_from_jks(jks_file, passphrase, key_alias, key_password=None):
    keystore = jks.KeyStore.load(jks_file, passphrase)
    pk_entry = keystore.private_keys[key_alias]
 
    '''if the key could not be decrypted using the store password, decrypt with a custom password now'''
    if not pk_entry.is_decrypted():
        pk_entry.decrypt(key_password)
 
    '''get private key'''
    pkey = OpenSSL.crypto.load_privatekey(_ASN1, pk_entry.pkey)
    pkey_pem = OpenSSL.crypto.dump_privatekey(_PEM, pkey)
 
    '''get certificate'''
    cert_chain = OpenSSL.crypto.load_certificate(_ASN1, pk_entry.cert_chain[0][1])
    cert = OpenSSL.crypto.dump_certificate(_ASN1, cert_chain)
 
    '''get public key'''
    pubkey_pem = OpenSSL.crypto.dump_publickey(_PEM, cert_chain.get_pubkey())
 
    ctx = {'private_key': pkey_pem, 'certificate': cert, 'public_key': pubkey_pem}
    return ctx
 
 
def get_ssl_context_from_pkcs12(pkcs12_location, passphrase):
    p12 = OpenSSL.crypto.load_pkcs12(open(pkcs12_location, 'rb').read(), passphrase.encode('utf-8'))
 
    '''get private key'''
    pkey_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, p12.get_privatekey())
 
    '''get certificate'''
    cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, p12.get_certificate())
 
    '''get public key'''
    pubkey_pem = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, p12.get_privatekey())
 
    ctx = {'private_key': pkey_pem, 'certificate': cert, 'public_key': pubkey_pem}
    return ctx
 
 
def get_ssl_context_from_x509_cert(crt, key):
    cert_pem = OpenSSL.crypto.load_certificate(_PEM, open(crt, 'rb').read())
    cert = OpenSSL.crypto.dump_certificate(_ASN1, cert_pem)
 
    pkey = OpenSSL.crypto.load_privatekey(_PEM, open(key, 'rb').read())
    pkey_pem = OpenSSL.crypto.dump_privatekey(_PEM, pkey)
 
    pubkey_pem = OpenSSL.crypto.dump_publickey(_PEM, pkey)
 
    ctx = {'private_key': pkey_pem, 'certificate': cert, 'public_key': pubkey_pem}
    return ctx
 
 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='X.509 authentication to fetch IDA token')
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-jks', '--jks', help=ARG_DESC_JKS, action='store')
    group.add_argument('-p12', '--pkcs12', help=ARG_DESC_PKCS12, action='store')
    group.add_argument('-crt', '--x509_cert', help=ARG_DESC_X509_CERT, action='store')
    parser.add_argument('-key', '--private_key', help=ARG_DESC_PRIVATE_KEY, required=False)
 
    pass_phrase_group = parser.add_mutually_exclusive_group(required=False)
    pass_phrase_group.add_argument('-pass_phrase', '--pass_phrase', help=ARG_DESC_PASS_PHRASE, action='store')
    pass_phrase_group.add_argument('-aws_secret', '--aws_secret_name', help=ARG_DESC_AWS_SECRET_NAME, action='store')
    parser.add_argument('-aws_region', '--aws_region', help=ARG_DESC_AWS_REGION, required=False, default='us-east-1')
    parser.add_argument('-aws_profile', '--aws_profile', help=ARG_DESC_AWS_PROFILE, required=False, default='adfs')
    parser.add_argument('-aws_secret_key_name', '--aws_secret_key_name', help=ARG_DESC_AWS_SECRET_NAME, required=False)
    parser.add_argument('-client_id', '--client_id', help=ARG_DESC_CLIENT_ID, required=True)
    parser.add_argument('-resource_id', '--resource_id', help=ARG_DESC_RESOURCE_ID, required=True)
    parser.add_argument('-alias', '--alias', help=ARG_DESC_KEY_ALIAS, required=True)
    parser.add_argument('-env', '--env', help=ARG_DESC_ENV, required=True)
    parser.add_argument('-v', '--verbose', help=ARG_DESC_VERBOSE, default=False)
    args = parser.parse_args()
 
    main(args)