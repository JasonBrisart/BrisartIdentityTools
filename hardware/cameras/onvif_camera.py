"""
File: hardware/cameras/onvif_camera.py

Purpose:
    A real CameraBase implementation for any ONVIF-compliant IP camera,
    implemented entirely with Python's standard library. Unlike the
    smart-card case (hardware/card_readers/pcsc_reader.py), ONVIF has no
    OS-proprietary equivalent to winscard.dll: it is a published,
    vendor-neutral SOAP/XML-over-HTTP standard, and Python's own
    urllib.request, xml.etree.ElementTree, and hashlib are sufficient to
    speak it completely. There is no boundary here that needs to be
    handed off to a lab-supplied binding -- this file goes all the way
    to the network socket using only the standard library.

    This module implements the small slice of ONVIF this project needs
    (WS-Security UsernameToken auth, GetCapabilities, GetProfiles,
    GetSnapshotUri, GetSystemDateAndTime) directly as SOAP XML built and
    parsed entirely with the standard library. No third-party package
    is imported anywhere in this file.

Communication relationships:
    Called by: hardware.hardware_manager.HardwareManager, once
    registered via hardware.registry.register() (not automatic -- see
    hardware/README.md).

    Calls out to: only Python's standard library --
    urllib.request (HTTP transport), xml.etree.ElementTree (SOAP
    request/response construction and parsing), hashlib + base64 + os
    (WS-Security UsernameToken digest computation). No third-party
    package of any kind is imported by this file.

    Does NOT call into biometrics/, vault/, packages/, or crypto/. This
    file has zero knowledge of identity records, sealed templates, or
    BSR2. Wiring a captured frame into the biometrics video/fingerprint
    pipeline is the caller's responsibility, not this file's.

Parameters / settings:
    DEFAULT_PORT (int, 80):
        ONVIF's conventional default port. Overridable per-camera, since
        many real deployments run ONVIF on a non-default port behind a
        NAT/firewall rule.
    DEFAULT_TIMEOUT_SECONDS (float, 5.0):
        Network timeout for every HTTP call this class makes (device
        service discovery, media service calls, and the snapshot fetch
        itself). Chosen conservatively: long enough to tolerate a camera
        waking from standby, short enough that a genuinely unreachable
        camera fails fast rather than hanging the caller.
    _SOAP_NAMESPACES:
        The small set of XML namespaces this project's SOAP envelopes
        and parsing need. Kept as a module constant rather than
        hardcoded per-call so every method uses the identical namespace
        map, avoiding the class of bug where one method's namespace
        prefix silently drifts from another's.

Edge-case behavior:
    - connect() returns False (not an exception) on any network-level
      or protocol-level failure (unreachable host, wrong credentials,
      timeout, malformed SOAP response), consistent with DeviceBase's
      contract that connect() is a boolean probe. The underlying
      exception is captured on `self.last_error`.
    - WS-Security UsernameToken digest auth is computed fresh for every
      SOAP call (a new nonce and timestamp each time), since ONVIF
      digest auth is timestamp-sensitive and a reused nonce/timestamp
      pair from an earlier call would be rejected by a compliant camera.
    - capture_image() authenticates against the snapshot URI using
      whichever of HTTP Digest or HTTP Basic the camera actually
      requests for that endpoint specifically, since real ONVIF cameras
      are inconsistent about which one they use for snapshot retrieval
      even when the SOAP calls themselves use WS-Security.
    - capture_image() returns raw JPEG bytes exactly as ONVIF's snapshot
      URI returns them -- no decoding, no re-encoding, no assumption
      about resolution. This project's own image codecs
      (biometrics/codecs/pgm.py, biometrics/codecs/png.py) do not
      currently accept JPEG; converting a captured frame into a format
      this project's biometric pipeline can consume is a separate,
      currently open piece of work, not something this file silently
      works around.
    - health_check() is a lightweight GetSystemDateAndTime call (no
      WS-Security required by the ONVIF spec for this specific
      operation), so a health check never itself exercises the
      snapshot-URI authentication path or requires valid credentials to
      report basic reachability.
    - GetCapabilities is called once during connect() to discover the
      camera's own advertised media service address, rather than
      assuming a fixed URL path, since ONVIF devices are not required
      to expose the media service at any particular path.
"""
import base64
import hashlib
import os
import urllib.request
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone

from hardware.base.camera_base import CameraBase
from hardware.exceptions import DeviceConnectionError

DEFAULT_PORT = 80
DEFAULT_TIMEOUT_SECONDS = 5.0

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


def _post_soap(url: str, body_xml: str, username=None, password=None,
                timeout_seconds=DEFAULT_TIMEOUT_SECONDS) -> ElementTree.Element:
    payload = _soap_envelope(body_xml, username, password)
    request = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/soap+xml; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            request, timeout=timeout_seconds
        ) as response:
            raw = response.read()
    except Exception as exc:  # noqa: BLE001 - re-raised as DeviceConnectionError
        raise DeviceConnectionError(f"SOAP request to {url} failed: {exc}") from exc
    try:
        return ElementTree.fromstring(raw)
    except ElementTree.ParseError as exc:
        raise DeviceConnectionError(
            f"malformed SOAP response from {url}: {exc}"
        ) from exc


class ONVIFCamera(CameraBase):
    """A CameraBase adapter for any ONVIF-compliant IP camera,
    implemented entirely with Python's standard library. Zero
    third-party packages of any kind."""

    def __init__(self, host, username, password, port=DEFAULT_PORT,
                 timeout_seconds=DEFAULT_TIMEOUT_SECONDS):
        self._host = host
        self._username = username
        self._password = password
        self._port = port
        self._timeout_seconds = timeout_seconds
        self._device_service_url = f"http://{host}:{port}/onvif/device_service"
        self._media_service_url = None
        self._snapshot_uri = None
        self.last_error = None

    @property
    def name(self) -> str:
        return f"ONVIF Camera ({self._host}:{self._port})"

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
        root = _post_soap(
            self._device_service_url, body,
            self._username, self._password, self._timeout_seconds,
        )
        media_xaddr = root.find(
            ".//tt:Media/tt:XAddr", _SOAP_NAMESPACES
        )
        if media_xaddr is None or not media_xaddr.text:
            raise DeviceConnectionError(
                f"{self._host} did not advertise a Media service "
                "address in GetCapabilities."
            )
        return media_xaddr.text.strip()

    def _get_first_profile_token(self) -> str:
        body = "<trt:GetProfiles/>"
        root = _post_soap(
            self._media_service_url, body,
            self._username, self._password, self._timeout_seconds,
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
        root = _post_soap(
            self._media_service_url, body,
            self._username, self._password, self._timeout_seconds,
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
            _post_soap(
                self._device_service_url, body,
                timeout_seconds=self._timeout_seconds,
            )  # unauthenticated per the ONVIF spec for this operation
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
        password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        password_manager.add_password(
            None, self._snapshot_uri, self._username, self._password
        )
        opener = urllib.request.build_opener(
            urllib.request.HTTPDigestAuthHandler(password_manager),
            urllib.request.HTTPBasicAuthHandler(password_manager),
        )
        request = urllib.request.Request(
            self._snapshot_uri, headers={"Accept": "image/jpeg"},
        )
        try:
            with opener.open(
                request, timeout=self._timeout_seconds
            ) as response:
                return response.read()
        except Exception as exc:  # noqa: BLE001 - reported to caller
            raise DeviceConnectionError(
                f"snapshot fetch from {self._snapshot_uri} failed: {exc}"
            ) from exc
