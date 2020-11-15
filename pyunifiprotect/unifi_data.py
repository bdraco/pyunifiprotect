"""Unifi Protect Data."""
import datetime
import enum
import logging
import struct
import time
import zlib
from collections import OrderedDict

WS_HEADER_SIZE = 8
_LOGGER = logging.getLogger(__name__)

EVENT_SMART_DETECT_ZONE = "smartDetectZone"
EVENT_MOTION = "motion"
EVENT_RING = "ring"

PROCESSED_EVENT_EMPTY = {
    "event_start": None,
    "event_score": 0,
    "event_thumbnail": None,
    "event_heatmap": None,
    "event_on": False,
    "event_ring_on": False,
    "event_type": None,
    "event_length": 0,
    "event_object": [],
}

MAX_SUPPORTED_CAMERAS = 256
MAX_EVENT_HISTORY_IN_STATE_MACHINE = MAX_SUPPORTED_CAMERAS * 2


@enum.unique
class ProtectWSPayloadFormat(enum.Enum):
    """Websocket Payload formats."""

    JSON = 1
    UTF8String = 2
    NodeBuffer = 3


def decode_ws_frame(frame, position):
    """Decode a unifi updates websocket frame."""
    # The format of the frame is
    # b: packet_type
    # b: payload_format
    # b: deflated
    # b: unknown
    # i: payload_size
    _, payload_format, deflated, _, payload_size = struct.unpack(
        "!bbbbi", frame[position : position + WS_HEADER_SIZE]
    )
    position += WS_HEADER_SIZE
    frame = frame[position : position + payload_size]
    if deflated:
        frame = zlib.decompress(frame)
    position += payload_size
    return frame, ProtectWSPayloadFormat(payload_format), position


def process_camera(server_id, host, camera):
    """Process the camera json."""
    # Get if camera is online
    online = camera["state"] == "CONNECTED"
    # Get Recording Mode
    recording_mode = str(camera["recordingSettings"]["mode"])
    # Get Infrared Mode
    ir_mode = str(camera["ispSettings"]["irLedMode"])
    # Get Status Light Setting
    status_light = str(camera["ledSettings"]["isEnabled"])

    # Get the last time motion occured
    lastmotion = (
        None
        if camera["lastMotion"] is None
        else datetime.datetime.fromtimestamp(int(camera["lastMotion"]) / 1000).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )
    # Get the last time doorbell was ringing
    lastring = (
        None
        if camera.get("lastRing") is None
        else datetime.datetime.fromtimestamp(int(camera["lastRing"]) / 1000).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )
    # Get when the camera came online
    upsince = (
        "Offline"
        if camera["upSince"] is None
        else datetime.datetime.fromtimestamp(int(camera["upSince"]) / 1000).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    )
    # Check if Regular Camera or Doorbell
    device_type = (
        "camera" if "doorbell" not in str(camera["type"]).lower() else "doorbell"
    )
    # Get Firmware Version
    firmware_version = str(camera["firmwareVersion"])

    # Get High FPS Video Mode
    featureflags = camera.get("featureFlags")
    has_highfps = "highFps" in featureflags.get("videoModes", "")
    video_mode = camera.get("videoMode") or "default"
    # Get HDR Mode
    has_hdr = featureflags.get("hasHdr")
    hdr_mode = camera.get("hdrMode") or False

    # Add rtsp streaming url if enabled
    rtsp = None
    channels = camera["channels"]
    for channel in channels:
        if channel["isRtspEnabled"]:
            rtsp = f"rtsp://{host}:7447/{channel['rtspAlias']}"
            break

    return {
        "name": str(camera["name"]),
        "type": device_type,
        "model": str(camera["type"]),
        "mac": str(camera["mac"]),
        "ip_address": str(camera["host"]),
        "firmware_version": firmware_version,
        "server_id": server_id,
        "recording_mode": recording_mode,
        "ir_mode": ir_mode,
        "status_light": status_light,
        "rtsp": rtsp,
        "up_since": upsince,
        "last_motion": lastmotion,
        "last_ring": lastring,
        "online": online,
        "has_highfps": has_highfps,
        "has_hdr": has_hdr,
        "video_mode": video_mode,
        "hdr_mode": hdr_mode,
    }


def event_from_ws_frames(state_machine, minimum_score, action_json, data_json):
    """Convert a websocket frame to internal format.

    Smart Detect Event Add:
    {'action': 'add', 'newUpdateId': '032615bb-910d-41bf-8710-b04959f24455', 'modelKey': 'event', 'id': '5fb0c89003085203870013d0'}
    {'type': 'smartDetectZone', 'start': 1605421197481, 'score': 98, 'smartDetectTypes': ['person'], 'smartDetectEvents': [], 'camera': '5f9f43f102f7d90387004da5', 'partition': None, 'id': '5fb0c89003085203870013d0', 'modelKey': 'event'}

    Smart Detect Event Update:
    {'action': 'update', 'newUpdateId': '84c74562-bb14-4426-8b92-84ae80d1fb4a', 'modelKey': 'event', 'id': '5fb0c92303b75203870013db'}
    {'end': 1605421366608, 'score': 52}

    Camera Motion Start (event):
    {'action': 'add', 'newUpdateId': '25b1142a-2d0d-4b85-b97e-401b03dd1f0b', 'modelKey': 'event', 'id': '5fb0c90603455203870013d7'}
    {'type': 'motion', 'start': 1605421315759, 'score': 0, 'smartDetectTypes': [], 'smartDetectEvents': [], 'camera': '5e539ed503617003870003ed', 'partition': None, 'id': '5fb0c90603455203870013d7', 'modelKey': 'event'}

    Camera Motion End (event):
    {'action': 'update', 'newUpdateId': 'aa1c159c-c575-443a-9e57-b63ed847549c', 'modelKey': 'event', 'id': '5fb0c90603455203870013d7'}
    {'end': 1605421330342, 'score': 46}

    Camera Ring (event)
    {'action': 'add', 'newUpdateId': 'da36377d-b947-4b05-ba11-c17b0d2703f9', 'modelKey': 'event', 'id': '5fb1964b03b352038700184d'}
    {'type': 'ring', 'start': 1605473867945, 'end': 1605473868945, 'score': 0, 'smartDetectTypes': [], 'smartDetectEvents': [], 'camera': '5f9f43f102f7d90387004da5', 'partition': None, 'id': '5fb1964b03b352038700184d', 'modelKey': 'event'}
    """

    if action_json["modelKey"] != "event":
        raise ValueError("Model key must be event or camera")

    action = action_json["action"]
    event_id = action_json["id"]

    if action == "add":
        camera_id = data_json.get("camera")
        if camera_id is None:
            return
        state_machine.add(event_id, data_json)
        event = data_json
    elif action == "update":
        event = state_machine.update(event_id, data_json)
        camera_id = event.get("camera")
    else:
        raise ValueError("The action must be add or update")

    _LOGGER.debug("Processing event: %s", event)
    return camera_id, process_event(
        event, minimum_score, int(time.time() * 1000) - 3000
    )


def process_event(event, minimum_score, event_ring_check_converted):
    """Convert an event to our format."""
    start = event.get("start")
    end = event.get("end")
    event_type = event.get("type")
    score = event.get("score")

    event_length = 0
    start_time = None

    if start:
        start_time = _process_timestamp(start)
    if end:
        event_length = (float(end) / 1000) - (float(start) / 1000)

    processed_event = {
        "event_on": False,
        "event_ring_on": False,
        "event_score": score,
        "event_type": event_type,
        "event_start": start_time,
        "event_length": event_length,
    }

    if event_type in (EVENT_MOTION, EVENT_SMART_DETECT_ZONE):
        processed_event["last_motion"] = start_time
        if end:
            if "smartDetectTypes" in event:
                processed_event["event_object"] = event["smartDetectTypes"]
        else:
            if score and int(score) >= minimum_score:
                processed_event["event_on"] = True
                if "smartDetectTypes" in event:
                    processed_event["event_object"] = event["smartDetectTypes"]
    else:
        processed_event["last_ring"] = start_time
        if end:
            if (
                start >= event_ring_check_converted
                and end >= event_ring_check_converted
            ):
                _LOGGER.debug("EVENT: DOORBELL HAS RUNG IN LAST 3 SECONDS!")
                processed_event["event_ring_on"] = True
            else:
                _LOGGER.debug("EVENT: DOORBELL WAS NOT RUNG IN LAST 3 SECONDS")
        else:
            _LOGGER.debug("EVENT: DOORBELL IS RINGING")
            processed_event["event_ring_on"] = True

    thumbail = event.get("thumbnail")
    if thumbail is not None:  # Only update if there is a new Motion Event
        processed_event["event_thumbnail"] = thumbail

    heatmap = event.get("heatmap")
    if heatmap is not None:  # Only update if there is a new Motion Event
        processed_event["event_heatmap"] = heatmap

    return processed_event


def _process_timestamp(time_stamp):
    return datetime.datetime.fromtimestamp(int(time_stamp) / 1000).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


class ProtectStateMachine:
    """A simple state machine for camera events."""

    def __init__(self):
        """Init the state machine."""
        self._events = FixSizeOrderedDict(max=MAX_EVENT_HISTORY_IN_STATE_MACHINE)

    def add(self, event_id, event_json):
        """Add an event to the state machine."""
        self._events[event_id] = event_json

    def update(self, event_id, new_event_json):
        """Update an event in the state machine and return the merged event."""
        event_json = self._events.get(event_id)
        if event_json is None:
            return None
        event_json.update(new_event_json)
        return event_json


class FixSizeOrderedDict(OrderedDict):
    def __init__(self, *args, max=0, **kwargs):
        self._max = max
        super().__init__(*args, **kwargs)

    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)
        if self._max > 0:
            if len(self) > self._max:
                self.popitem(False)
