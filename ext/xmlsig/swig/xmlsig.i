/*
 * (C) Copyright 2006 VeriSign, Inc.
 * Developed by Sxip Identity
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
%module(docstring="xmlsig is a wrapper around the xmlsec library, providing a simple interface for digital signatures") xmlsig
%include "std_string.i"
%include "std_vector.i"
%{
#include "DSig.h"
#include "Signer.h"
#include "Key.h"
#include "XmlDoc.h"
#include "Verifier.h"
#include "KeyStore.h"
#include "TrustVerifier.h"
#include <libxml/tree.h>
%}

#if defined(SWIGPYTHON)
typedef xmlDoc *xmlDocPtr;
%include python.i
#endif

#if defined(SWIGPERL)
%include perl.i
#endif

#if defined(SWIGRUBY)
%include ruby.i
#endif

%include "countptr.i"

int dsigInit (void) throw (LibError);
int dsigShutdown (void);

%init %{
    dsigInit();
    %}

%include "exceptions.i"

%rename(X509CertificateBase) X509Certificate;
%rename(X509Certificate) CountPtrTo<X509Certificate>;
class X509Certificate {
public:
    X509Certificate();
    X509Certificate(const X509Certificate& cert) 
        throw(MemoryError);
    ~X509Certificate();
    int loadFromFile(std::string fileName, std::string format) 
        throw(IOError, KeyError);
    std::string getSubjectDN();
    std::string getIssuerDN();
    int getVersion();
    int isValid();
    int getBasicConstraints();
    KeyPtr getKey () const;
};
class CountPtrTo<X509Certificate>
{
 public:
    ~CountPtrTo ();

    X509Certificate* operator-> ();
};
%extend CountPtrTo<X509Certificate> {
    CountPtrTo<X509Certificate> ()
    {
        return new CountPtrTo<X509Certificate>(new X509Certificate());
    }
    CountPtrTo<X509Certificate> (const CountPtrTo<X509Certificate>& cert) throw(MemoryError)
    {
        return new CountPtrTo<X509Certificate>(new X509Certificate(*cert));
    }
}
typedef CountPtrTo<X509Certificate> X509CertificatePtr;
namespace std {
    %template(X509CertificateVector) vector<X509CertificatePtr>;
};

%rename(KeyBase) Key;
%rename(Key) CountPtrTo<Key>;
class Key {
public:
    Key();
    Key(X509CertificatePtr cert)
        throw(LibError);
    Key(std::vector<X509CertificatePtr> certs)
        throw(MemoryError, LibError, ValueError, KeyError);
    ~Key();

    int loadFromFile(std::string fileName, std::string format, std::string password)
        throw(IOError);
    int loadFromKeyInfoFile(std::string fileName)
        throw(MemoryError, IOError, LibError, XMLError);
    int loadHMACFromString(std::string hMACString)
        throw(MemoryError, LibError, KeyError);

    int setName (std::string name)
        throw(KeyError, LibError);
    std::string getName ();
    int isValid ();
    X509CertificatePtr getCertificate ()
        throw(KeyError);
    vector<X509CertificatePtr> getCertificateChain ();

    void dump();
};
class CountPtrTo<Key>
{
 public:
    ~CountPtrTo ();

    Key* operator-> ();
};
%extend CountPtrTo<Key> {
    CountPtrTo<Key> ()
    {
        return new CountPtrTo<Key>(new Key());
    }
    CountPtrTo<Key> (const CountPtrTo<Key>& key)
    {
        return new CountPtrTo<Key>(new Key(*key));
    }
    CountPtrTo<Key> (X509CertificatePtr cert)
    {
        return new CountPtrTo<Key>(new Key(cert));
    }
    CountPtrTo<Key> (std::vector<X509CertificatePtr> certs)
    {
        return new CountPtrTo<Key>(new Key(certs));
    }
}
typedef CountPtrTo<Key> KeyPtr;
namespace std {
    %template(KeyVector) vector<KeyPtr>;
};

%rename(KeyStoreBase) KeyStore;
%rename(KeyStore) CountPtrTo<KeyStore>;
class KeyStore {
public:
    KeyStore()
        throw(MemoryError, KeyError);
    ~KeyStore();
    int addTrustedCert(X509CertificatePtr cert)
        throw(LibError);
    int addUntrustedCert(X509CertificatePtr cert)
        throw(LibError);
    int addTrustedCertFromFile(std::string fileName, std::string format)
        throw(IOError);
    int addUntrustedCertFromFile(std::string fileName, std::string format)
        throw(IOError);
    int addKey(KeyPtr key)
        throw(IOError, LibError, MemoryError, KeyError);
    int addKeyFromFile(std::string fileName, std::string format, std::string name)
        throw(IOError, LibError, MemoryError, KeyError);
    int addKeyFromFile(std::string fileName, std::string format, std::string name, std::string password)
        throw(IOError, LibError, MemoryError, KeyError);
    int saveToFile(std::string fileName)
        throw(IOError);
    int loadFromFile(std::string fileName)
        throw(IOError);
};
class CountPtrTo<KeyStore>
{
 public:
    ~CountPtrTo ();

    KeyStore* operator-> ();
};
%extend CountPtrTo<KeyStore> {
    CountPtrTo<KeyStore> ()
    {
        return new CountPtrTo<KeyStore>(new KeyStore());
    }
}
typedef CountPtrTo<KeyStore> KeyStorePtr;

%rename(XmlDocBase) XmlDoc;
%rename(XmlDoc) CountPtrTo<XmlDoc>;
class XmlDoc {
public:
    XmlDoc();
    ~XmlDoc();
#if defined(SWIGPYTHON)
    int loadFromXmlDocPtr(xmlDocPtr) 
        throw(ValueError, LibError);
    xmlDocPtr getDoc();
#endif
    int loadFromString(std::string xmlData) 
        throw(LibError);
    int loadFromFile(std::string fileName) 
        throw(IOError, LibError);
    std::string toString();
    int toFile(std::string fileName) 
        throw(IOError, LibError);
    void dump();
    int addIdAttr(std::string attrName, std::string nodeName, std::string nsHref) 
        throw(ValueError, XMLError);
};
class CountPtrTo<XmlDoc>
{
 public:
    ~CountPtrTo ();

    XmlDoc* operator-> ();
};
%extend CountPtrTo<XmlDoc> {
    CountPtrTo<XmlDoc> ()
    {
        return new CountPtrTo<XmlDoc>(new XmlDoc());
    }
    CountPtrTo<XmlDoc> (const CountPtrTo<XmlDoc>& doc)
    {
        return new CountPtrTo<XmlDoc>(new XmlDoc(*doc));
    }
}
typedef CountPtrTo<XmlDoc> XmlDocClassPtr;

%rename(XPathBase) XPath;
%rename(XPath) CountPtrTo<XPath>;
class XPath {
public:
    XPath();
    XPath(std::string expr);
    ~XPath();
    int addNamespace (std::string prefix, std::string uri);
    std::string getXPath ();
    void setXPath (std::string expr);
};
class CountPtrTo<XPath>
{
 public:
    ~CountPtrTo ();

    XPath* operator-> ();
};
%extend CountPtrTo<XPath> {
    CountPtrTo<XPath> ()
    {
        return new CountPtrTo<XPath>(new XPath());
    }
    CountPtrTo<XPath> (const CountPtrTo<XPath>& xpath)
    {
        return new CountPtrTo<XPath>(new XPath(*xpath));
    }
    CountPtrTo<XPath> (std::string expr)
    {
        return new CountPtrTo<XPath>(new XPath(expr));
    }
}
typedef CountPtrTo<XPath> XPathPtr;

%rename(XmlElementBase) XmlElement;
%rename(XmlElement) CountPtrTo<XmlElement>;
class XmlElement
{
public:
    XmlElement ();
    ~XmlElement ();

    xmlNodePtr getNode ();
    std::string getTagName ();
    std::string getAttribute (std::string name);
    std::string getAttribute (std::string name, std::string nameSpace);
    std::string getNodePath ();
};
class CountPtrTo<XmlElement>
{
 public:
    ~CountPtrTo ();

    XmlElement* operator-> ();
};
%extend CountPtrTo<XmlElement> {
    CountPtrTo<XmlElement> ()
    {
        return new CountPtrTo<XmlElement>(new XmlElement());
    }
}
typedef CountPtrTo<XmlElement> XmlElementPtr;
namespace std {
    %template(XmlElementVector) vector<XmlElementPtr>;
};

%newobject Signer::sign;
class Signer {
public:
    Signer(XmlDocClassPtr doc, KeyPtr key);
    Signer(XmlDocClassPtr doc, KeyPtr key, KeyPtr verifyKey);
    Signer(XmlDocClassPtr doc, KeyPtr key, X509CertificatePtr cert)
        throw(KeyError, ValueError, MemoryError, LibError);
    Signer(XmlDocClassPtr doc, KeyPtr key, std::vector<X509CertificatePtr> cert)
        throw(KeyError, ValueError, MemoryError, LibError);
    ~Signer();

    XmlDocClassPtr sign() 
        throw(MemoryError, DocError, XPathError, LibError, KeyError);
    XmlDocClassPtr sign(XPathPtr xPath) 
        throw(MemoryError, DocError, XPathError, LibError, KeyError);
    XmlDocClassPtr sign(XPathPtr xPath, bool insertBefore) 
        throw(MemoryError, DocError, XPathError, LibError, KeyError);

    int signInPlace() 
        throw(DocError, XPathError, LibError, KeyError);
    int signInPlace(XPathPtr xPath) 
        throw(DocError, XPathError, LibError, KeyError);
    int signInPlace(XPathPtr xPath, bool insertBefore) 
        throw(DocError, XPathError, LibError, KeyError);

    int setKeyStore(KeyStorePtr keyStore) 
        throw(ValueError);
    int addCertFromFile(std::string fileName, std::string fileFormat)
        throw(KeyError, IOError);
    int addCert(X509CertificatePtr cert)
        throw(KeyError, ValueError, MemoryError, LibError);
    int useExclusiveCanonicalizer(std::string prefixes);
    void addReference(XPathPtr xPath);
    void attachPublicKey (int value);
};

%newobject Verifier::getVerifyingKey;
class Verifier {
public:
    Verifier(XmlDocClassPtr doc) 
        throw(MemoryError);
    Verifier(XmlDocClassPtr doc, XPathPtr xpath) 
        throw(MemoryError);

    int setKeyStore(KeyStorePtr keyStore) 
        throw(ValueError);
    int verify() 
        throw(LibError, MemoryError, KeyError, DocError, XMLError);
    int verify(KeyPtr key) 
        throw(LibError, MemoryError, KeyError, DocError, XMLError);

    KeyPtr getVerifyingKey ()
        throw(DocError, XMLError, LibError);
    int isReferenced(XPathPtr xpath)
        throw(DocError, XMLError, LibError);
    std::vector<XmlElementPtr> getReferencedElements ()
        throw(XMLError, LibError);
    X509CertificatePtr getCertificate ()
        throw(DocError, XMLError, LibError);
    std::vector<X509CertificatePtr> getCertificateChain ()
        throw(DocError, XMLError, LibError);
    void skipCertCheck (int skip);
};

class TrustVerifier
{
public:
    TrustVerifier ();
    virtual ~TrustVerifier ();
    virtual int verifyTrust ()
        throw(TrustVerificationError);
    virtual int verifyTrust (KeyPtr key)
        throw(TrustVerificationError);
    virtual int verifyTrust (std::vector<X509CertificatePtr> chain)
        throw(TrustVerificationError);
};


class SimpleTrustVerifier : public TrustVerifier
{
public:
    SimpleTrustVerifier (std::vector<KeyPtr> keys);
    ~SimpleTrustVerifier ();

    int verifyTrust ()
        throw(TrustVerificationError);
    int verifyTrust (KeyPtr key)
        throw(TrustVerificationError, LibError);
    int verifyTrust (std::vector<X509CertificatePtr> chain)
        throw(TrustVerificationError, LibError);
};


class X509TrustVerifier : public TrustVerifier
{
public:
    X509TrustVerifier (std::vector<X509CertificatePtr> certs);
    ~X509TrustVerifier ();

    int verifyTrust ()
        throw(TrustVerificationError);
    int verifyTrust (KeyPtr key)
        throw(TrustVerificationError, LibError);
    int verifyTrust (std::vector<X509CertificatePtr> chain)
        throw(TrustVerificationError, LibError, KeyError);
};
