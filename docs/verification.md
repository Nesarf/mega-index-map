# Verifying a signed release

Releases of this project are built and signed on the machine that produced them, under the identity

```
subject    : O=S.M.Y.T., CN=S.M.Y.T. Code Signing
thumbprint : 4EA54E72A1EEFAE280B99631F7680DBFF461C4F1
valid to   : 2031-10-05
```

and published with four files:

| file | what it is | size (0.3.7) |
|---|---|---|
| `mega-index-map-0.3.7.tgz` | the package tarball, as `npm pack` produced it | 359.6 KB |
| `mega-index-map-0.3.7.tgz.p7s` | a PKCS#7 signature over those bytes, with an RFC-3161 timestamp inside | 367.1 KB |
| `mega-index-map-0.3.7.tgz.sha256` | the tarball's SHA-256, in `<hash>  <name>` form | 0.1 KB |
| `smyt-codesign.cer` | the public certificate, so the signature can be checked | 1.1 KB |

The 0.3.7 tarball's SHA-256 is `0ABC3965E32A7C8335E95D74E79194F1D6E1FFFA619BE39A01BB495F692538DE`, and it
was built from commit `279072f`.

## Three ways to check it, all three exercised

**1. The hash - no certificate needed.** The `.sha256` file is in the standard form:

```
sha256sum -c mega-index-map-0.3.7.tgz.sha256            # Linux, macOS, Git Bash
certutil -hashfile mega-index-map-0.3.7.tgz SHA256      # Windows, built in
```

**2. openssl - no toolchain needed.** The signature is an ordinary enveloped CMS: it carries its own copy of
the signed bytes, so openssl verifies it directly, without the original file:

```
openssl cms -verify -inform DER -in mega-index-map-0.3.7.tgz.p7s -noverify -out /dev/null
# CMS Verification successful
```

`-noverify` skips the *certificate chain* check, which a self-signed certificate cannot pass on a machine
that has not imported it; the signature over the bytes is still verified. To read the signer:

```
openssl pkcs7 -inform DER -in mega-index-map-0.3.7.tgz.p7s -print_certs -noout
# subject=CN=S.M.Y.T. Code Signing, O=S.M.Y.T.
```

**3. The signing toolchain, if you have it.** `smyt-blob.ps1 -Verify <tarball>`, in the same directory as the
`.p7s`, does what openssl does and adds two checks openssl does not make: it compares the copy of the bytes
inside the signature with the file on disk, and it insists that the signer's thumbprint is the published one.

## What the signature proves, and what it does not

It proves that these bytes were signed by the holder of the certificate above, at the recorded time, and that
they have not changed since.

It does not claim:

- **that Windows trusts it.** The certificate is self-signed. The machine that signs holds its own root; a
  stranger's Windows does not, and will keep warning about the download. A `.p7s` is also not Authenticode:
  there is no Digital Signatures property page for it and SmartScreen ignores it. Authenticode needs a PE
  image to write into, and a JavaScript package does not have one - manufacturing an executable only to have
  something to sign would be a decoration, not a guarantee.
- **any warranty.** The code is MIT (see LICENSE); a signature says who, not that it is fit for anything.
- **that the contents are what you wanted** - only that they are what was signed. Read the code, or compare
  the tarball against the tag it names.
- **that the timestamp outlives the certificate.** The timestamp is inside the signature, but the signature
  records a certificate that exists now.

## Importing the certificate (optional, and only if you mean it)

```
certutil -addstore -user Root smyt-codesign.cer
certutil -addstore -user TrustedPublisher smyt-codesign.cer
```

Nothing in this project depends on that import; it only changes what your own machine reports.
