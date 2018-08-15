Certificate Transparency
========================

.. currentmodule:: cryptography.x509.certificate_transparency

`Certificate Transparency`_ is a set of protocols specified in :rfc:`6962`
which allow X.509 certificates to be sent to append-only logs and have small
cryptographic proofs that a certificate has been publicly logged. This allows
for external auditing of the certificates that a certificate authority has
issued.

.. class:: SignedCertificateTimestamp

    .. versionadded:: 2.0

    SignedCertificateTimestamps (SCTs) are small cryptographically signed
    assertions that the specified certificate has been submitted to a
    Certificate Transparency Log, and that it will be part of the public log
    within some time period, this is called the "maximum merge delay" (MMD) and
    each log specifies its own.

    .. attribute:: version

        :type: :class:`~cryptography.x509.certificate_transparency.Version`

        The SCT version as an enumeration. Currently only one version has been
        specified.

    .. attribute:: log_id

        :type: bytes

        An opaque identifier, indicating which log this SCT is from. This is
        the SHA256 hash of the log's public key.

        The bytes of the SCT's signature.

        .. doctest::

            >>> from cryptography import x509
            >>> from cryptography.hazmat.backends import default_backend
            >>> from cryptography.hazmat.primitives import hashes
            >>> cert = x509.load_pem_x509_certificate(cryptography_cert_pem, default_backend())
            >>> # Get the SignedCertificateTimestamps extension from the certificate
            >>> ext = cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
            >>> for sct in ext.value:
            ...     print(sct)

    .. attribute:: timestamp

        :type: :class:`datetime.datetime`

        A naïve datetime representing the time in UTC at which the log asserts
        the certificate had been submitted to it.

    .. attribute:: entry_type

        :type:
            :class:`~cryptography.x509.certificate_transparency.LogEntryType`

        The type of submission to the log that this SCT is for. Log submissions
        can either be certificates themselves or "pre-certificates" which
        indicate a binding-intent to issue a certificate for the same data,
        with SCTs embedded in it.

    .. attribute:: signature

        .. versionadded:: 2.3

        :type: bytes

    .. attribute:: signature_hash_algorithm

        .. versionadded:: 2.3

        :type: :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm`

        Returns the
        :class:`~cryptography.hazmat.primitives.hashes.HashAlgorithm` which
        was used in signing this SCT.

        .. doctest::

            >>> from cryptography.hazmat.primitives import hashes
            >>> isinstance(sct.signature_hash_algorithm, hashes.SHA1)
            True

    .. attribute:: signature_algorithm_oid

        .. versionadded:: 2.3

        :type: :class:`ObjectIdentifier`

        Returns the :class:`ObjectIdentifier` of the signature algorithm used
        to sign the SCT. This will be one of the OIDs from
        :class:`~cryptography.x509.oid.SignatureAlgorithmOID`.


        .. doctest::

            >>> sct.signature_algorithm_oid
            <ObjectIdentifier(oid=1.2.840.113549.1.1.11, name=sha256WithRSAEncryption)>


.. class:: Version

    .. versionadded:: 2.0

    An enumeration for SignedCertificateTimestamp versions.

    .. attribute:: v1

        For version 1 SignedCertificateTimestamps.

.. class:: LogEntryType

    .. versionadded:: 2.0

    An enumeration for SignedCertificateTimestamp log entry types.

    .. attribute:: X509_CERTIFICATE

        For SCTs corresponding to X.509 certificates.

    .. attribute:: PRE_CERTIFICATE

        For SCTs corresponding to pre-certificates.


.. _`Certificate Transparency`: https://www.certificate-transparency.org/
