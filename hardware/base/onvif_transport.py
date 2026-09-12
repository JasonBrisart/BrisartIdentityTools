"""
File: hardware/base/onvif_transport.py

Purpose:
    Defines the contract for the ONE operation this project deliberately
    does not implement for ONVIF cameras: opening a network connection
    and exchanging bytes with the camera itself. Every other piece of
    ONVIF logic -- SOAP envelope construction, WS-Security UsernameToken
    digest generation, XML response parsing, capability/profile
    selection, snapshot-URI resolution, and error translation -- is
    implemented in pure Python, with zero network calls, in
    hardware/cameras/onvif_camera.py, and needs no transport at all to
    exercise that logic in isolation.

    An ONVIFTransport implementation is the one piece of code in this
    project's camera support path that must open a socket, perform an
    HTTP request, and talk to a physical network endpoint. This project
    ships the CONTRACT only. Implementing it -- actually calling
    urllib, a proxy-aware HTTP client, an organization's camera
    gateway, or any other network mechanism -- is left to the
    organization deploying this software, under their own network and
    audit posture. See hardware/README.md, "Why the ONVIF transport is
    not shipped," for the full reasoning. This mirrors, deliberately,
    the same boundary hardware/base/pcsc_binding.py already draws for
    smart-card readers.

Communication relationships:
    Implemented by: an organization-supplied transport class (not part
    of this repository's shipped code), constructed and passed into
    hardware.cameras.onvif_camera.ONVIFCamera's constructor.

    Called by: hardware.cameras.onvif_camera.ONVIFCamera, which is the
    only file in this project that calls an ONVIFTransport's methods.
    onvif_camera.py contains no urllib import, no socket call, and no
    network-library usage of its own -- all of that lives entirely on
    whichever transport an operator supplies.

Parameters / settings:
    None. This module defines an interface only; it has no
    configuration, hostnames, credentials, ports, certificates, proxy
    settings, or timeout values of its own. Those values are supplied
    by ONVIFCamera when invoking the transport and may be interpreted
    according to the deploying organization's own networking and
    security policies.

Edge-case behavior:
    - ONVIFTransportError is the single exception type a transport is
      expected to raise for any low-level failure (connection refused,
      DNS failure, TLS failure, timeout, non-2xx HTTP status, etc.).
      onvif_camera.py catches ONVIFTransportError specifically and
      translates it into this project's own DeviceConnectionError
      hierarchy, so a caller of ONVIFCamera never needs to know or
      handle transport-specific exception types.
    - post() and get() are expected to return the FULL raw response
      body as bytes -- not a decoded string, not an open response
      object, not an iterator or file handle. onvif_camera.py is
      responsible for all XML parsing and interpretation of that body;
      the transport must not parse SOAP, select ONVIF profiles, or
      decode image data.
    - The transport is responsible for closing every connection,
      stream, socket, or other resource it opens before returning
      control to ONVIFCamera, and must not silently return a partial
      response body.
    - Redirect handling, proxy behavior, HTTP authentication method
      selection, TLS verification, certificate selection, retry
      behavior, and network-level logging are entirely
      deployment-controlled concerns; this contract expresses no
      opinion on any of them.
    - An implementation may refuse an insecure connection, an
      unapproved host, an invalid certificate, or any request that
      violates organization policy by raising ONVIFTransportError; a
      refusal is indistinguishable to ONVIFCamera from any other
      transport-level failure.
"""
from abc import ABC, abstractmethod


class ONVIFTransportError(Exception):
    """Raised by an ONVIFTransport implementation for any low-level
    network failure (connection refused, DNS failure, TLS failure,
    timeout, non-2xx HTTP status, or any other transport-level error).
    onvif_camera.py catches this exception type specifically and
    translates it into DeviceConnectionError."""


class ONVIFTransport(ABC):
    """The raw network operations hardware/cameras/onvif_camera.py
    needs. An implementation of this class is the only place in a
    deployment of BrisartIdentityTools where a network connection to
    an ONVIF camera is actually opened. This project ships no
    implementation of this class -- see hardware/README.md.
    """

    @abstractmethod
    def post(self, url: str, body: bytes, headers: dict) -> bytes:
        """Send `body` to `url` as an HTTP POST with the given headers
        and return the FULL raw response body as bytes. Raise
        ONVIFTransportError on any failure (connection, timeout, TLS,
        non-2xx status, or otherwise)."""

    @abstractmethod
    def get(self, url: str, headers: dict, username: str = None,
            password: str = None) -> bytes:
        """Retrieve `url` as an HTTP GET with the given headers and
        return the FULL raw response body as bytes. Raise
        ONVIFTransportError on any failure.

        `username`/`password` are passed explicitly (rather than
        pre-encoded into `headers`) because real ONVIF cameras are
        inconsistent about whether their snapshot endpoint expects HTTP
        Basic or HTTP Digest authentication, and negotiating that
        (a Digest challenge/response round trip, in particular)
        requires the transport to hold the raw credentials, not a
        single pre-committed Authorization header value. Used by
        ONVIFCamera to retrieve snapshot bytes from a camera-provided
        snapshot URI."""
