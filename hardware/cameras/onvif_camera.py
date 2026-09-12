"""
File: hardware/cameras/onvif_camera.py

Purpose:
    A CameraBase implementation of the ONVIF protocol -- a published,
    vendor-neutral standard for IP camera interoperability (Axis,
    Hikvision, Dahua, and most budget IP cameras). This module owns
    every piece of ONVIF protocol logic BrisartIdentityTools needs:
    WS-Security UsernameToken digest generation, SOAP envelope
    construction, GetCapabilities/GetProfiles/GetSnapshotUri/
    GetSystemDateAndTime request bodies, XML response parsing, and
    translation of transport-level failures into this project's own
    exception hierarchy. All of it is implemented with Python's
    standard library only (hashlib, base64, os, datetime,
    xml.etree.ElementTree) -- zero third-party packages.

    This module deliberately does NOT open a network connection. The
    one operation it cannot do without leaving pure protocol logic --
    actually sending bytes to the camera and getting bytes back -- is
    delegated to a hardware.base.onvif_transport.ONVIFTransport
    instance supplied by the caller at construction time. This project
    ships the transport contract (hardware/base/onvif_transport.py)
    but no implementation of it, mirroring the same boundary
    hardware/base/pcsc_binding.py already draws for smart-card readers.
    See hardware/README.md, "Why the ONVIF transport is not shipped,"
    for the full reasoning.

Communication relationships:
    Called by: hardware.hardware_manager.HardwareManager, once
    registered via hardware.registry.register() (not automatic -- see
    hardware/README.md), and constructed with an ONVIFTransport
    instance the operator supplies.

    Calls out to: ONLY the ONVIFTransport instance passed into its
    constructor, for the two network operations (`post` for SOAP calls,
    `get` for the snapshot fetch). This file contains no urllib import,
    no socket call, and no network-library usage anywhere in its
    source. Every other line is plain Python: SOAP/XML string
    construction, hashlib/base64 digest computation, and
    xml.etree.ElementTree parsing.

    Does NOT call into biometrics/, vault/, packages/, or crypto/. This
    file has zero knowledge of identity records, sealed templates, or
    BSR2. Wiring a captured frame into the biometrics video/fingerprint
    pipeline is the caller's responsibility, not this file's.

Why the transport is required, not optional, at construction:
    A caller with no ONVIFTransport implementation cannot use this
    class, by design -- there is no default, no silent fallback to
    urllib, and no partially-working mode. Requiring the transport
    explicitly is what keeps this file itself free of any network call:
    it never has to open a socket or make an HTTP request because it
    never performs that operation at all.

Parameters / settings:
    DEFAULT_PORT (int, 80):
        ONVIF's conventional default port. Used only to build the
        device-service URL passed to the transport; this module never
        opens the connection itself.
    _SOAP_NAMESPACES:
        The small set of XML namespaces this project's SOAP envelopes
        and parsing need. Kept as a module constant so every method
        uses the identical namespace map, avoiding the class of bug
        where one method's namespace prefix silently drifts from
        another's.

Edge-case behavior:
    - connect() returns False (not an exception) on any transport-level
      or protocol-level failure (unreachable host, wrong credentials,
      malformed SOAP response), consistent with DeviceBase's contract
      that connect() is a boolean probe. The underlying exception is
      captured on `self.last_error`.
    - ONVIFTransportError raised by the transport is caught at every
      call site and translated into DeviceConnectionError, so a caller
      of this class never needs to know or handle transport-specific
      exception types.
    - WS-Security UsernameToken digest auth is computed fresh for every
      SOAP call (a new nonce and timestamp each time), since ONVIF
      digest auth is timestamp-sensitive and a reused nonce/timestamp
      pair from an earlier call would be rejected by a compliant
      camera.
    - capture_image() passes the raw username/password to the
      transport's get() as explicit arguments, not pre-encoded into a
      header, since real ONVIF cameras are inconsistent about whether
      the snapshot endpoint expects HTTP Basic or HTTP Digest
      authentication and the transport needs the raw credentials to
      negotiate either. This module never decides which scheme is
      used; that is the transport's responsibility.
    - capture_image() returns raw JPEG bytes exactly as the transport's
      get() returns them -- no decoding, no re-encoding, no assumption
      about resolution. This project's own image codecs
      (biometrics/codecs/pgm.py, biometrics/codecs/png.py) do not
      currently accept JPEG; converting a captured frame into a format
      this project's biometric pipeline can consume is a separate,
      currently open piece of work, not something this file silently
      works around.
    - health_check() is a lightweight GetSystemDateAndTime call (no
      WS-Security required by the ONVIF spec for this specific
      operation), so a health check never itself requires valid
      credentials to report basic reachability.
    - GetCapabilities is called once during connect() to discover the
      camera's own advertised media service address, rather than
      assuming a fixed URL path, since ONVIF devices are not required
      to expose the media service at any particular path.
"""
import base64
import hashlib
import os
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone

from hardware.base.camera_base import CameraBase
from hardware.base.onvif_transport import ONVIFTransport, ONVIFTransportError
from hardware.exceptions import DeviceConnectionError

DEFAULT_PORT = 80

_SOAP_NAMESPACES = {
    "soap": "http://www.w3.org/2003/05/soap-envelope",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/"
            "oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "wsu": "http://docs.oasis-open.org/wss/2004/01/"
           "oasis-200401-wss-wssecurity-utility-1.0.xsd",
    "tds": "http://www.onvif.org/ver10/device/wsdl",
    "trt": "http://www.onvif.org/ver10/media/wsdl",
    "tt": "http://www.onvif.org/ver10/schema",
}
for _prefix, _uri in _SOAP_NAMESPACES.items():
    ElementTree.register_namespace(_prefix, _uri)


def _ws_security_header(username: str, password: str) -> str:
    """Build a WS-Security UsernameToken header using PasswordDigest,
    per the ONVIF/WS-Security spec: digest = Base64(SHA1(nonce +
    created + password)). A fresh nonce and timestamp are generated on
    every call.
    """
    nonce = os.urandom(16)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = hashlib.sha1(
        nonce + created.encode("utf-8") + password.encode("utf-8")
    ).digest()
    return f"""
    <wsse:Security soap:mustUnderstand="1">
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/
oasis-200401-wss-username-token-profile-1.0#PasswordDigest">
          {base64.b64encode(digest).decode('ascii')}
        </wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/
oasis-200401-wss-soap-message-security-1.0#Base64Binary">
          {base64.b64encode(nonce).decode('ascii')}
        </wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
    """


def _soap_envelope(body_xml: str, username=None, password=None) -> bytes:
    header = (
        _ws_security_header(username, password)
        if username is not None else ""
    )
    envelope = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="{_SOAP_NAMESPACES['soap']}"
               xmlns:wsse="{_SOAP_NAMESPACES['wsse']}"
               xmlns:wsu="{_SOAP_NAMESPACES['wsu']}"
               xmlns:tds="{_SOAP_NAMESPACES['tds']}"
               xmlns:trt="{_SOAP_NAMESPACES['trt']}">
  <soap:Header>{header}</soap:Header>
  <soap:Body>{body_xml}</soap:Body>
</soap:Envelope>"""
    return envelope.encode("utf-8")


class ONVIFCamera(CameraBase):
    """A CameraBase adapter implementing the ONVIF protocol. Owns all
    SOAP/XML/WS-Security logic; owns zero network connectivity. Every
    network operation is delegated to a required, caller-supplied
    hardware.base.onvif_transport.ONVIFTransport instance.
    """

    def __init__(self, transport: ONVIFTransport, host, username,
                 password, port=DEFAULT_PORT):
        if not isinstance(transport, ONVIFTransport):
            raise TypeError(
                "ONVIFCamera requires a hardware.base.onvif_transport."
                "ONVIFTransport instance; got "
                f"{type(transport).__name__!r} instead. This project "
                "ships the transport CONTRACT only -- see "
                "hardware/README.md, 'Why the ONVIF transport is not "
                "shipped,' for how to supply one."
            )
        self._transport = transport
        self._host = host
        self._username = username
        self._password = password
        self._port = port
        self._device_service_url = f"http://{host}:{port}/onvif/device_service"
        self._media_service_url = None
        self._snapshot_uri = None
        self.last_error = None

    @property
    def name(self) -> str:
        return f"ONVIF Camera ({self._host}:{self._port})"

    def _post_soap(self, url: str, body_xml: str,
                    username=None, password=None) -> ElementTree.Element:
        payload = _soap_envelope(body_xml, username, password)
        headers = {"Content-Type": "application/soap+xml; charset=utf-8"}
        try:
            raw = self._transport.post(url, payload, headers)
        except ONVIFTransportError as exc:
            raise DeviceConnectionError(
                f"SOAP request to {url} failed: {exc}"
            ) from exc
        try:
            return ElementTree.fromstring(raw)
        except ElementTree.ParseError as exc:
            raise DeviceConnectionError(
                f"malformed SOAP response from {url}: {exc}"
            ) from exc

    def connect(self) -> bool:
        try:
            self._media_service_url = self._discover_media_service_url()
            token = self._get_first_profile_token()
            self._snapshot_uri = self._get_snapshot_uri(token)
            self.last_error = None
            return True
        except DeviceConnectionError as exc:
            self.last_error = exc
            self._media_service_url = None
            self._snapshot_uri = None
            return False

    def _discover_media_service_url(self) -> str:
        body = "<tds:GetCapabilities><tds:Category>Media</tds:Category></tds:GetCapabilities>"
        root = self._post_soap(
            self._device_service_url, body, self._username, self._password,
        )
        media_xaddr = root.find(".//tt:Media/tt:XAddr", _SOAP_NAMESPACES)
        if media_xaddr is None or not media_xaddr.text:
            raise DeviceConnectionError(
                f"{self._host} did not advertise a Media service "
                "address in GetCapabilities."
            )
        return media_xaddr.text.strip()

    def _get_first_profile_token(self) -> str:
        body = "<trt:GetProfiles/>"
        root = self._post_soap(
            self._media_service_url, body, self._username, self._password,
        )
        profile = root.find(".//trt:Profiles", _SOAP_NAMESPACES)
        if profile is None or "token" not in profile.attrib:
            raise DeviceConnectionError(
                f"{self._host} reported zero ONVIF media profiles."
            )
        return profile.attrib["token"]

    def _get_snapshot_uri(self, token: str) -> str:
        body = (
            f'<trt:GetSnapshotUri><trt:ProfileToken>{token}'
            f'</trt:ProfileToken></trt:GetSnapshotUri>'
        )
        root = self._post_soap(
            self._media_service_url, body, self._username, self._password,
        )
        uri_element = root.find(".//trt:Uri", _SOAP_NAMESPACES)
        if uri_element is None or not uri_element.text:
            raise DeviceConnectionError(
                f"{self._host} did not return a snapshot URI for "
                f"profile {token!r}."
            )
        return uri_element.text.strip()

    def disconnect(self) -> None:
        self._media_service_url = None
        self._snapshot_uri = None

    def health_check(self) -> bool:
        try:
            body = "<tds:GetSystemDateAndTime/>"
            self._post_soap(self._device_service_url, body)
            # unauthenticated per the ONVIF spec for this operation
            self.last_error = None
            return True
        except DeviceConnectionError as exc:
            self.last_error = exc
            return False

    def capture_image(self) -> bytes:
        if self._snapshot_uri is None:
            raise DeviceConnectionError(
                f"{self.name} is not connected; call connect() first."
            )
        headers = {"Accept": "image/jpeg"}
        try:
            return self._transport.get(
                self._snapshot_uri, headers,
                username=self._username, password=self._password,
            )
        except ONVIFTransportError as exc:
            raise DeviceConnectionError(
                f"snapshot fetch from {self._snapshot_uri} failed: {exc}"
            ) from exc
