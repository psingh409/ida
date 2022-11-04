# Use Managed Base Image Oracle JDK 11
FROM python:latest


# Human-readable title of the image (string)
LABEL org.opencontainers.image.title="IDA-using-python"

ADD x509_ida_token.py /
ADD bootstrap.ida.uat.aws.jpmchase.net.cer /
ADD bootstrap.ida.uat.aws.jpmchase.net.privatekey /
RUN pip3 install pyjks 
RUN pip3 install boto3 
RUN pip3 install pyjks 
RUN pip3 install requests 
RUN pip3 install PyJWT 
#CMD [ "ls -ltr"]
CMD [ "python", "./x509_ida_token.py", "-crt","bootstrap.ida.uat.aws.jpmchase.net.cer", "-key", "bootstrap.ida.uat.aws.jpmchase.net.privatekey", "-pass_phrase","null", "-client_id", "CC-110252-A016175-174870-UAT", "-resource_id", "JPMC:URI:RS-103752-21345-GTIDPOServiceMgt-UAT", "-env", "uat", "-alias", "null", "-v", "true" ]


