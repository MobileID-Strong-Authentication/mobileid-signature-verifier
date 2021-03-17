# mobileid-signature-verifier
A sample implementation how to verify a CMS/PKCS7 signature, e.g. a Swisscom Mobile ID RSA oder ECC signature.

##### TrustStore

The Trust Anchor used by the verifier sample is based on the Swisscom Root CA 2 certificate. The TrustStore in the subfolder `jks` contains the root certificate plus an intermediate CA certificate.
The TrustStore is protected with the password **secret** and contains the following certificates:

```
Alias name: swisscom root ca 2
Owner: CN=Swisscom Root CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
Issuer: CN=Swisscom Root CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
Certificate fingerprints (MD5): 5B:04:69:EC:A5:83:94:63:18:A7:86:D0:E4:F2:6E:19
```
```
Alias name: swisscom_rubin_ca_3
Owner: C=ch, O=Swisscom, OU=Digital Certificate Services, CN=Swisscom Rubin CA 3
Issuer: CN=Swisscom Root CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
Certificate fingerprints (MD5): CD:8E:50:05:01:38:63:D5:88:04:C7:FD:E4:3F:B7:F5
```

##### Usage

###### Example Usage
```
$ javac -d ./class -cp ".:./lib/*" ./src/ch/swisscom/mid/verifier/*.java

$ jar cfe ./jar/midverifier-v1.3.jar ch.swisscom.mid.verifier.MobileIdCmsVerifier -C ./class .

$ java -cp ".:./lib/*:./jar/*" ch.swisscom.mid.verifier.MobileIdCmsVerifier
Usage: ch.swisscom.mid.verifier.MobileIdCmsVerifier [OPTIONS]

Options:
  -cms=VALUE or -stdin   - base64 encoded CMS/PKCS7 signature string, either as VALUE or via standard input
  -jks=VALUE             - optional path to truststore file (default is 'jks/truststore.jks')
  -jkspwd=VALUE          - optional truststore password (default is 'secret')

Example:
  java ch.swisscom.mid.verifier.MobileIdCmsVerifier -cms=MIII...
  echo -n MIII... | java ch.swisscom.mid.verifier.MobileIdCmsVerifier -stdin
```

##### Example Output

```
X509 Certificate #1
X509 Issuer: CN=Swisscom TEST Rubin CA 3, OU=Digital Certificate Services, O=Swisscom, C=ch
X509 Subject DN: C=CH, CN=MIDCHESSOMTKWTZ1:PN, SERIALNUMBER=MIDCHESSOMTKWTZ1
X509 SerialNumber: 1269016737403337228
SignerCert: Yes
PubKey: Sun RSA public key, 2048 bits
  modulus: 18411986096864509129206161852724956078062030473911992954913583488717137962367298423585014748629707635736157687963613785815770489392514775818441330742317798593708301421025749767589853358740654460703298193502018560273815261375172658454921111061848158785694667226899690963699977089503105572991571542273554861586864814613900174765981285323877135385387381448912036514027302209959523783314701559103991879380609275954020186431799253289458266034511404464595678537824400780373454534152742497558040921390450862027903219634821804337928811121253022884716686187149897173054713081027538146017992840953352609188039516867575166988777
  public exponent: 65537
PubKeyEncoded: 30820122300d06092a864886f70d01010105000382010f003082010a028201010091d9dcbc0d9d6b3982cdbb1921d5865daa51aeb0510cbb576d9baf6051d73099dec6eb61f59b13a5e0bccd4f0161992b3a379687039342654d385e9b7a4f9344bb73c448fb6b2d6d3a802c52c92f2b6956075d87a6a2c521a69bf4517d13366fb15c26b369de806333a2c214e7360661b74953c3120086f4ae88ce3146a0b5826e58de5d8fdc69cccb7c9fdf4f950df63b770760393af546cd57b977017cb7dad39dee339ebc2e5a3bccae942e26c881f30964a03db41a280cccec16fa68795c1c315c81dcd29d7b61b4f744150d2e6dd578adcf10938072a3fde03cbd60774bccd1dbdf3c0371e46f1482e9d7fcb008031d65c16220ebc69c345a63747af1e90203010001

X509 Certificate #2
X509 Issuer: CN=Swisscom TEST Root CA 2, OU=Digital Certificate Services, O=Swisscom, C=ch
X509 Subject DN: CN=Swisscom TEST Rubin CA 3, OU=Digital Certificate Services, O=Swisscom, C=ch
X509 SerialNumber: 214264239052327233270836397181193616930
SignerCert: No
PubKey: Sun RSA public key, 2048 bits
  modulus: 26437963545314835826831785598767082564979971617745261357776316273090493345768464788815591752930303356721176873662636065672055526538071881564202059420785959774252820235746764746448125709167903569003841637664263093284829112656245599284802031046090833074972472711790517385295703851058457188451851770943292679848202060649806988572983468055251250653519835575279893889139957548717819820605522097421539565731487868513552118434995635499561181499785372096122955565627031446047071652142555439120658510728368035156351753852261115437398361129143209041064213827411222695736642519992123749857042440655813704984940728295321041432003
  public exponent: 65537
PubKeyEncoded: 30820122300d06092a864886f70d01010105000382010f003082010a0282010100d16dd3c2ed60159e34cd3c1852965c113922e22c0f8a4a51c7beb9852462b00b070ce14ee5db96989de8b6691790db98a77b460a9664d2174129cf1ea2298a4aab090b72785e136132ff884c7a8f7a56207c184c0e631657637278ce51aa807a4d87e93d8c827a0f6ef0267c819d174a4cb0495814b446468f469397712fb0c4470c71811c921ac175e1b6e9b9b7be10ee39373dafe95ccaabe0948b1a5805eb80a3f4e982b9f5fe48245218ee3b2ecf8a69269c4627cfaa98acedfba3b64dca8af2ab8b8799c018e7106b331fe0a3352a08c17c3057efb2099901f2e86fb52b1dceb7d5ddce0186c0ab4577e54310eeb187612b6e29d61e8e4bda880070edc30203010001

X509 SignerCert SerialNumber: 1269016737403337228
X509 SignerCert Issuer: CN=Swisscom TEST Rubin CA 3, OU=Digital Certificate Services, O=Swisscom, C=ch
X509 SignerCert Subject DN: C=CH, CN=MIDCHESSOMTKWTZ1:PN, SERIALNUMBER=MIDCHESSOMTKWTZ1
X509 SignerCert Validity Not Before: Thu Jan 05 15:15:58 CET 2017
X509 SignerCert Validity Not After: Sun Jan 05 15:15:58 CET 2020
X509 SignerCert Validity currently valid: true
X509 SignerCert Key Alogrithm: RSA
User's unique Mobile ID SerialNumber: MIDCHESSOMTKWTZ1
Signed Data: Test: Sie haben bei PostFinance das Login in E-Finance angefordert. Bitte bestätigen Sie dieses.
Signature Valid: true
X509 SignerCert Valid (Path+OCSP): true
```
