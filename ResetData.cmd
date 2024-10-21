del /f .\\PKI\\*.txt.old.*

del /f .\\PKI\\CA\\*.crt
del /f .\\PKI\\CA\\*.key
del /f .\\PKI\\CERT\\*.crt
del /f .\\PKI\\CERT\\*.key
del /f .\\PKI\\ROOT\\*.crt
del /f .\\PKI\\ROOT\\*.key

del /f .\\PKI\\OCSP\\*.crt
del /f .\\PKI\\OCSP\\*.key
del /f .\\PKI\\OCSP\\*.req
del /f .\\PKI\\OCSP\\*.res

del /f .\\PKI\\TIMSTAMP\\*.crt
del /f .\\PKI\\TIMSTAMP\\*.key

del /f .\\PKI\\TIMSTAMP\\log\\*.req
del /f .\\PKI\\TIMSTAMP\\log\\*.res

del /f .\\PKI\\KEY\\*.key

del /f .\\PKI\\WebPublic\\CRT\\*.crt
del /f .\\PKI\\WebPublic\\CRL\\*.crl