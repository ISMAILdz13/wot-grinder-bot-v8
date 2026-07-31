#!/usr/bin/env python3
"""
WoT Battle Awareness System v5.0
================================
Real-time BigWorld packet decoder for World of Tanks.

Decodes the actual game protocol to track:
- Enemy positions (Position packets, type 0x0a)
- Vehicle health (updateVehicleHealth, Avatar method 5)
- Ammo count (updateVehicleAmmo, Avatar method 8)
- Gun reload status (updateVehicleGunReloadTime, Avatar method 6)
- Vehicle entities (EntityCreate, type 0x5)
- Map/arena info (Map, type 0x0f)
- Shot results (showShotResults, Avatar method 22)
- Chat messages (Chat interface)

Based on the real WoT .def entity definition files and the
BigWorld/Core engine network protocol (from replays_unpack project).

Protocol: NetPacket = [4B size] [4B type] [4B time] [payload]
"""

import struct
import math
import time
import logging
import random
from io import BytesIO
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Callable
from collections import defaultdict

logger = logging.getLogger("WoTCombat")

# ===========================================================================
# BIGWORLD PACKET TYPES (from replays_unpack/clients/wot/network/packets/)
# ===========================================================================

PKT_BASE_PLAYER_CREATE  = 0x0
PKT_CELL_PLAYER_CREATE  = 0x1
PKT_ENTITY_CONTROL      = 0x2
PKT_ENTITY_ENTER        = 0x3
PKT_ENTITY_LEAVE        = 0x4
PKT_ENTITY_CREATE       = 0x5
PKT_ENTITY_PROPERTY     = 0x7
PKT_ENTITY_METHOD       = 0x8
PKT_POSITION            = 0x0a
PKT_MAP                 = 0x0f
PKT_NESTED_PROPERTY     = 0x24

# ===========================================================================
# AVATAR CLIENT METHODS (from Avatar.def, indexed by order of declaration)
# These are the messageId values in EntityMethod packets (type 0x8)
# ===========================================================================

AVATAR_METHODS = {
    0:  ("update", ["STRING"]),
    1:  ("onKickedFromServer", ["STRING", "BOOL", "UINT32"]),
    2:  ("onIGRTypeChanged", ["STRING"]),
    3:  ("onAutoAimVehicleLost", ["UINT8"]),
    4:  ("receiveAccountStats", ["UINT32", "STRING"]),
    5:  ("updateVehicleHealth", ["OBJECT_ID", "INT16", "INT8", "BOOL", "BOOL"]),
    6:  ("updateVehicleGunReloadTime", ["OBJECT_ID", "FLOAT32", "FLOAT32"]),
    7:  ("updateVehicleClipReloadTime", ["OBJECT_ID", "FLOAT32", "FLOAT32", "BOOL"]),
    8:  ("updateVehicleAmmo", ["OBJECT_ID", "INT32", "UINT16", "UINT8", "INT16", "INT16"]),
    9:  ("updateDualGunState", ["OBJECT_ID", "UINT8", "ARRAY<UINT8>", "ARRAY"]),
    10: ("onSwitchViewpoint", ["OBJECT_ID", "VECTOR3"]),
    11: ("onBootcampEvent", ["ARRAY<UINT64>"]),
    12: ("updateVehicleOptionalDeviceStatus", ["OBJECT_ID", "UINT8", "BOOL"]),
    13: ("updateVehicleMiscStatus", ["OBJECT_ID", "UINT8", "INT32", "ARRAY<FLOAT32>"]),
    14: ("updateVehicleSetting", ["OBJECT_ID", "UINT8", "INT32"]),
    15: ("updateTargetingInfo", ["FLOAT32"] * 9),
    16: ("updateGunMarker", ["OBJECT_ID", "VECTOR3", "VECTOR3", "FLOAT32"]),
    17: ("updateTargetVehicleID", ["OBJECT_ID"]),
    18: ("updateOwnVehiclePosition", ["VECTOR3", "VECTOR3", "FLOAT32", "FLOAT32"]),
    19: ("showOwnVehicleHitDirection", ["FLOAT32", "OBJECT_ID", "UINT16", "UINT32", "BOOL", "BOOL", "OBJECT_ID", "UINT8"]),
    20: ("showVehicleDamageInfo", ["OBJECT_ID", "UINT8", "EXTRA_ID", "OBJECT_ID", "UINT8"]),
    21: ("showOtherVehicleDamagedDevices", ["OBJECT_ID", "ARRAY", "ARRAY"]),
    22: ("showShotResults", ["ARRAY<UINT64>"]),
    23: ("updatePlaneTrajectory", ["UINT16", "UINT8", "FLOAT64", "VECTOR3", "VECTOR2", "FLOAT64", "VECTOR3", "VECTOR2", "BOOL"]),
    24: ("showHittingArea", ["UINT16", "VECTOR3", "VECTOR3", "FLOAT64"]),
    25: ("showCarpetBombing", ["UINT16", "VECTOR3", "VECTOR3", "FLOAT64"]),
}

# VEHICLE entity properties (from Vehicle.def, indexed by order)
VEHICLE_PROPS = {
    0:  ("isStrafing", "BOOL"),
    1:  ("physicsMode", "UINT8"),
    2:  ("siegeState", "UINT8"),
    3:  ("gunAnglesPacked", "UINT16"),
    4:  ("publicInfo", "PUBLIC_VEHICLE_INFO"),
    5:  ("health", "INT16"),
    6:  ("isCrewActive", "BOOL"),
    7:  ("engineMode", "TUPLE"),
    8:  ("damageStickers", "ARRAY"),
    9:  ("publicStateModifiers", "ARRAY"),
    10: ("compDescr", "STRING"),
    11: ("stunInfo", "STUN_INFO"),
    12: ("status", "INT8"),
    13: ("invisibility", "FLOAT32"),
    14: ("radioDistance", "FLOAT32"),
    15: ("circularVisionRadius", "FLOAT32"),
    16: ("detectedVehicles", "ARRAY"),
    17: ("isObservedByEnemy", "BOOL"),
    18: ("rammingBonus", "FLOAT32"),
    19: ("ammo", "ARRAY"),
    20: ("botKind", "UINT8"),
}

# AVATAR entity properties (from Avatar.def, indexed by order)
AVATAR_PROPS = {
    0:  ("state", "UINT16"),
    1:  ("name", "STRING"),
    2:  ("sessionID", "STRING"),
    3:  ("account", "MAILBOX"),
    4:  ("playerVehicle", "MAILBOX"),
    5:  ("arena", "MAILBOX"),
    6:  ("arenaVehiclesDBIDs", "PYTHON"),
    7:  ("arenaUniqueID", "UINT64"),
    8:  ("arenaTypeID", "INT32"),
    9:  ("arenaBonusType", "UINT8"),
    10: ("arenaGuiType", "UINT8"),
    11: ("arenaExtraData", "PYTHON"),
    12: ("weatherPresetID", "UINT8"),
    13: ("denunciationsLeft", "INT16"),
    14: ("clientCtx", "STRING"),
    15: ("tkillIsSuspected", "BOOL"),
    16: ("team", "UINT8"),
    17: ("playerVehicleID", "OBJECT_ID"),
    18: ("playerVehicleTypeCompDescr", "UINT16"),
    19: ("isGunLocked", "BOOL"),
    20: ("ownVehicleGear", "UINT8"),
    21: ("ownVehicleAuxPhysicsData", "UINT64"),
    22: ("ammo", "ARRAY"),
    23: ("ammoViews", "AVATAR_AMMO_VIEWS"),
}

# Chat methods (from Chat.def)
CHAT_BASE_METHODS = {
    0:  ("joinChatChannel", ["OBJECT_ID", "STRING"]),
    1:  ("leaveChatChannel", ["OBJECT_ID"]),
    2:  ("onChatAction", ["CHAT_ACTION_DATA"]),
    3:  ("chatCommandFromClient", ["INT64", "UINT8", "OBJECT_ID", "INT64", "INT16", "STRING", "STRING"]),
    4:  ("chatCommand", ["MAILBOX", "INT64", "UINT8", "OBJECT_ID", "INT64", "INT16", "STRING", "STRING"]),
    5:  ("inviteCommand", ["INT64", "UINT8", "INT8", "STRING", "INT64", "INT16", "STRING", "STRING"]),
    6:  ("ackCommand", ["INT64", "UINT8", "FLOAT64", "INT64", "INT64"]),
    7:  ("keepAlive", ["OBJECT_ID", "INT16"]),
}

# Shot result flags (bits in showShotResults UINT64 values)
SHOT_RESULT = {
    0:  "MISS",
    1:  "NON_PIERCING",
    2:  "PIERCED",
    3:  "PIERCED_CRITICAL",
    4:  "PIERCED_SCREEN",
    5:  "RICOCHET",
    6:  "DESTROYED_TANK",
    7:  "DESTROYED_MODULE",
}


# ===========================================================================
# DATA STRUCTURES
# ===========================================================================

@dataclass
class Vector3:
    x: float = 0.0
    y: float = 0.0
    z: float = 0.0

    def distance_to(self, other: 'Vector3') -> float:
        return math.sqrt((self.x-other.x)**2 + (self.y-other.y)**2 + (self.z-other.z)**2)

    def angle_to(self, other: 'Vector3') -> float:
        return math.atan2(other.z - self.z, other.x - self.x)

    def __repr__(self):
        return f"({self.x:.1f}, {self.y:.1f}, {self.z:.1f})"


@dataclass
class TrackedVehicle:
    """Represents a vehicle tracked by the battle awareness system."""
    entity_id: int
    vehicle_id: int = 0
    is_enemy: bool = False
    is_alive: bool = True
    is_spotted: bool = False
    position: Vector3 = field(default_factory=Vector3)
    direction: Vector3 = field(default_factory=Vector3)
    yaw: float = 0.0
    pitch: float = 0.0
    roll: float = 0.0
    health: int = 100
    max_health: int = 100
    ammo: List[int] = field(default_factory=list)
    reload_start: float = 0.0
    reload_end: float = 0.0
    is_reloading: bool = False
    clip_size: int = 1
    clip_current: int = 1
    gun_angles: int = 0
    is_strafing: bool = False
    siege_state: int = 0
    tank_type: str = ""
    tank_name: str = ""
    last_seen: float = 0.0
    last_position_update: float = 0.0


@dataclass
class ChatMessage:
    """A chat message from a teammate or the system."""
    sender_id: int = 0
    message: str = ""
    channel: int = 0
    timestamp: float = 0.0
    is_team: bool = True


@dataclass
class ShotResult:
    """Result of a shot fired."""
    target_id: int = 0
    result_type: int = 0
    result_name: str = ""
    damage: int = 0
    timestamp: float = 0.0


# ===========================================================================
# WEAK SPOT DATABASE
# ===========================================================================

class WeakSpotDatabase:
    """
    Database of tank weak spots for targeting.
    Based on WoT Tank Academy weak spots guide and armor.wotinspector.com data.

    Common weak spots for ALL tanks:
    - Lower glacis (LFP): front lower hull, usually thin armor
    - Cupola: turret top, weak on many heavy tanks
    - Side hull: thin side armor, easy to penetrate
    - Rear hull: weakest armor, highest damage chance
    - Commander's hatch: small but very weak
    - Viewport: small weak spot on turret front
    - MG port: machine gun port, weak on some tanks

    Tank-specific weak spots are keyed by vehicle type compact descriptor.
    """

    # Universal weak spots (apply to most tanks)
    UNIVERSAL_WEAK_SPOTS = {
        "lower_glacis": {
            "name": "Lower Glacis Plate",
            "armor": 60,
            "priority": 1,  # highest priority
            "description": "Front lower hull — usually the weakest frontal armor",
        },
        "cupola": {
            "name": "Cupola",
            "armor": 40,
            "priority": 2,
            "description": "Turret top — weak on many heavy tanks",
        },
        "commander_hatch": {
            "name": "Commander's Hatch",
            "armor": 30,
            "priority": 3,
            "description": "Small but very weak spot on turret",
        },
        "side_hull": {
            "name": "Side Hull",
            "armor": 40,
            "priority": 1,
            "description": "Thin side armor — easy to penetrate",
        },
        "rear_hull": {
            "name": "Rear Hull",
            "armor": 20,
            "priority": 1,
            "description": "Weakest armor — highest penetration chance",
        },
        "viewport": {
            "name": "Viewport",
            "armor": 50,
            "priority": 3,
            "description": "Small weak spot on turret front",
        },
        "mg_port": {
            "name": "Machine Gun Port",
            "armor": 45,
            "priority": 2,
            "description": "Weak spot on front hull",
        },
        "cheek": {
            "name": "Turret Cheek",
            "armor": 80,
            "priority": 4,
            "description": "Turret front sides — varies by tank",
        },
        "shoulder": {
            "name": "Shoulder",
            "armor": 70,
            "priority": 3,
            "description": "Upper hull sides near turret",
        },
    }

    # Tank-specific weak spots by tank class
    CLASS_WEAK_SPOTS = {
        "heavy": {
            "front": ["lower_glacis", "cupola", "commander_hatch", "viewport", "mg_port"],
            "side": ["side_hull", "shoulder"],
            "rear": ["rear_hull"],
        },
        "medium": {
            "front": ["lower_glacis", "viewport", "mg_port"],
            "side": ["side_hull"],
            "rear": ["rear_hull"],
        },
        "light": {
            "front": ["lower_glacis", "cupola", "viewport"],
            "side": ["side_hull"],
            "rear": ["rear_hull"],
        },
        "td": {
            "front": ["lower_glacis", "mg_port", "viewport"],
            "side": ["side_hull"],
            "rear": ["rear_hull"],
        },
        "spg": {
            "front": ["lower_glacis", "cupola"],
            "side": ["side_hull"],
            "rear": ["rear_hull"],
        },
    }

    def __init__(self):
        self._tank_db = self._build_tank_db()

    def _build_tank_db(self) -> Dict:
        """Build a database of known tank weak spots."""
        # This would normally be loaded from tanks.gg or wotinspector API
        # For now, we use the universal + class-based weak spots
        return {}

    def get_weak_spots(self, tank_class: str, facing: str = "front") -> List[Dict]:
        """
        Get the weak spots for a tank, based on which side we're facing.

        Args:
            tank_class: heavy, medium, light, td, spg
            facing: front, side, rear (which side of the enemy we can see)

        Returns:
            List of weak spot dicts sorted by priority (highest first)
        """
        spots = self.CLASS_WEAK_SPOTS.get(tank_class, self.CLASS_WEAK_SPOTS["medium"])
        spot_names = spots.get(facing, spots.get("front", ["lower_glacis"]))

        result = []
        for name in spot_names:
            spot = self.UNIVERSAL_WEAK_SPOTS.get(name)
            if spot:
                result.append({
                    "name": spot["name"],
                    "key": name,
                    "armor": spot["armor"],
                    "priority": spot["priority"],
                    "description": spot["description"],
                })

        # Sort by priority (1 = highest)
        result.sort(key=lambda s: s["priority"])
        return result

    def get_aim_point(self, tank_class: str, facing: str,
                      target_pos: Vector3, my_pos: Vector3) -> Tuple[float, float, str]:
        """
        Calculate the aim point offset for the best weak spot.

        Returns: (yaw_offset, pitch_offset, spot_name)
        """
        spots = self.get_weak_spots(tank_class, facing)
        if not spots:
            return 0.0, 0.0, "center"

        best = spots[0]  # highest priority

        # Calculate offset based on weak spot location
        # lower_glacis = aim lower → negative pitch offset
        # cupola = aim higher → positive pitch offset
        # side_hull = aim center → minimal offset
        # rear_hull = aim center → minimal offset

        yaw_offset = 0.0
        pitch_offset = 0.0

        if best["key"] == "lower_glacis":
            pitch_offset = -0.15  # aim down
        elif best["key"] == "cupola":
            pitch_offset = 0.20   # aim up
        elif best["key"] == "commander_hatch":
            pitch_offset = 0.15
        elif best["key"] == "viewport":
            pitch_offset = 0.05
        elif best["key"] == "mg_port":
            pitch_offset = -0.05
        elif best["key"] == "side_hull":
            yaw_offset = 0.1      # slight lead for side shot
        elif best["key"] == "rear_hull":
            pitch_offset = -0.05
        elif best["key"] == "shoulder":
            yaw_offset = 0.05
            pitch_offset = 0.05

        return yaw_offset, pitch_offset, best["name"]


# ===========================================================================
# PACKET DECODER
# ===========================================================================

class BattleDecoder:
    """
    Decodes raw BigWorld network packets into structured data.
    Uses the real WoT packet format from the replays_unpack project.

    NetPacket format: [4B size (uint32)] [4B type (uint32)] [4B time (float32)] [payload]
    """

    @staticmethod
    def decode_stream(data: bytes) -> List[Dict]:
        """Decode a stream of BigWorld packets."""
        packets = []
        stream = BytesIO(data)

        while stream.tell() < len(data):
            # Read packet header
            header = stream.read(12)
            if len(header) < 12:
                break

            size, pkt_type, pkt_time = struct.unpack("<IIf", header)
            raw_data = stream.read(size)

            if len(raw_data) < size:
                break

            pkt = BattleDecoder._decode_packet(pkt_type, pkt_time, raw_data)
            if pkt:
                packets.append(pkt)

        return packets

    @staticmethod
    def decode_single(data: bytes) -> Optional[Dict]:
        """Decode a single BigWorld packet from raw bytes."""
        if len(data) < 12:
            return None

        size, pkt_type, pkt_time = struct.unpack("<IIf", data[:12])
        raw_data = data[12:12+size]

        return BattleDecoder._decode_packet(pkt_type, pkt_time, raw_data)

    @staticmethod
    def _decode_packet(pkt_type: int, pkt_time: float, raw_data: bytes) -> Optional[Dict]:
        """Decode a single packet based on its type."""
        stream = BytesIO(raw_data)

        try:
            if pkt_type == PKT_POSITION:
                return BattleDecoder._decode_position(stream, pkt_time)
            elif pkt_type == PKT_ENTITY_CREATE:
                return BattleDecoder._decode_entity_create(stream, pkt_time)
            elif pkt_type == PKT_ENTITY_PROPERTY:
                return BattleDecoder._decode_entity_property(stream, pkt_time)
            elif pkt_type == PKT_ENTITY_METHOD:
                return BattleDecoder._decode_entity_method(stream, pkt_time)
            elif pkt_type == PKT_MAP:
                return BattleDecoder._decode_map(stream, pkt_time)
            elif pkt_type == PKT_ENTITY_LEAVE:
                return BattleDecoder._decode_entity_leave(stream, pkt_time)
            elif pkt_type == PKT_BASE_PLAYER_CREATE:
                return BattleDecoder._decode_base_player(stream, pkt_time)
            elif pkt_type == PKT_CELL_PLAYER_CREATE:
                return BattleDecoder._decode_cell_player(stream, pkt_time)
            elif pkt_type == PKT_ENTITY_ENTER:
                return BattleDecoder._decode_entity_enter(stream, pkt_time)
            elif pkt_type == PKT_ENTITY_CONTROL:
                return {"type": "entity_control", "time": pkt_time}
            elif pkt_type == PKT_NESTED_PROPERTY:
                return BattleDecoder._decode_nested_property(stream, pkt_time)
            else:
                return {"type": "unknown", "pkt_type": pkt_type, "time": pkt_time,
                        "size": len(raw_data), "data": raw_data.hex()[:80]}
        except Exception as e:
            logger.debug("Decode error type=0x%x: %s", pkt_type, e)
            return {"type": "error", "pkt_type": pkt_type, "time": pkt_time, "error": str(e)}

    @staticmethod
    def _read_vector3(stream: BytesIO) -> Vector3:
        return Vector3(*struct.unpack("<fff", stream.read(12)))

    @staticmethod
    def _read_binary_stream(stream: BytesIO) -> bytes:
        length = struct.unpack("<I", stream.read(4))[0]
        return stream.read(length)

    @staticmethod
    def _decode_position(stream: BytesIO, pkt_time: float) -> Dict:
        """Decode Position packet (type 0x0a)."""
        entity_id = struct.unpack("<i", stream.read(4))[0]
        vehicle_id = struct.unpack("<i", stream.read(4))[0]
        position = BattleDecoder._read_vector3(stream)
        position_error = BattleDecoder._read_vector3(stream)
        yaw, pitch, roll = struct.unpack("<fff", stream.read(12))
        is_error = struct.unpack("<b", stream.read(1))[0]

        return {
            "type": "position",
            "time": pkt_time,
            "entity_id": entity_id,
            "vehicle_id": vehicle_id,
            "position": position,
            "position_error": position_error,
            "yaw": yaw,
            "pitch": pitch,
            "roll": roll,
            "is_error": bool(is_error),
        }

    @staticmethod
    def _decode_entity_create(stream: BytesIO, pkt_time: float) -> Dict:
        """Decode EntityCreate packet (type 0x5)."""
        entity_id = struct.unpack("<i", stream.read(4))[0]
        entity_type = struct.unpack("<h", stream.read(2))[0]
        vehicle_id = struct.unpack("<i", stream.read(4))[0]
        space_id = struct.unpack("<i", stream.read(4))[0]
        position = BattleDecoder._read_vector3(stream)
        direction = BattleDecoder._read_vector3(stream)
        unknown1 = struct.unpack("<i", stream.read(4))[0]
        state = BattleDecoder._read_binary_stream(stream)

        return {
            "type": "entity_create",
            "time": pkt_time,
            "entity_id": entity_id,
            "entity_type": entity_type,
            "vehicle_id": vehicle_id,
            "space_id": space_id,
            "position": position,
            "direction": direction,
            "unknown1": unknown1,
            "state": state.hex() if state else "",
        }

    @staticmethod
    def _decode_entity_property(stream: BytesIO, pkt_time: float) -> Dict:
        """Decode EntityProperty packet (type 0x7)."""
        object_id = struct.unpack("<I", stream.read(4))[0]
        message_id = struct.unpack("<I", stream.read(4))[0]
        data = BattleDecoder._read_binary_stream(stream)

        return {
            "type": "entity_property",
            "time": pkt_time,
            "object_id": object_id,
            "message_id": message_id,
            "data": data.hex() if data else "",
            "data_raw": data,
        }

    @staticmethod
    def _decode_entity_method(stream: BytesIO, pkt_time: float) -> Dict:
        """Decode EntityMethod packet (type 0x8)."""
        entity_id = struct.unpack("<I", stream.read(4))[0]
        message_id = struct.unpack("<I", stream.read(4))[0]
        data = BattleDecoder._read_binary_stream(stream)

        # Look up method name from Avatar.def
        method_info = AVATAR_METHODS.get(message_id, (f"unknown_{message_id}", []))
        method_name = method_info[0]
        arg_types = method_info[1]

        # Try to parse the method arguments
        parsed_args = BattleDecoder._parse_method_args(data, arg_types)

        return {
            "type": "entity_method",
            "time": pkt_time,
            "entity_id": entity_id,
            "message_id": message_id,
            "method_name": method_name,
            "arg_types": arg_types,
            "args": parsed_args,
            "data": data.hex() if data else "",
        }

    @staticmethod
    def _parse_method_args(data: bytes, arg_types: List[str]) -> Dict:
        """Parse method arguments based on their types from the .def file."""
        if not data:
            return {}

        stream = BytesIO(data)
        args = {}

        try:
            for i, arg_type in enumerate(arg_types):
                if stream.tell() >= len(data):
                    break

                if arg_type == "OBJECT_ID":
                    args[f"arg{i}_object_id"] = struct.unpack("<I", stream.read(4))[0]
                elif arg_type == "INT16":
                    args[f"arg{i}_int16"] = struct.unpack("<h", stream.read(2))[0]
                elif arg_type == "INT32":
                    args[f"arg{i}_int32"] = struct.unpack("<i", stream.read(4))[0]
                elif arg_type == "UINT8":
                    args[f"arg{i}_uint8"] = struct.unpack("<B", stream.read(1))[0]
                elif arg_type == "UINT16":
                    args[f"arg{i}_uint16"] = struct.unpack("<H", stream.read(2))[0]
                elif arg_type == "UINT32":
                    args[f"arg{i}_uint32"] = struct.unpack("<I", stream.read(4))[0]
                elif arg_type == "FLOAT32":
                    args[f"arg{i}_float32"] = struct.unpack("<f", stream.read(4))[0]
                elif arg_type == "FLOAT64":
                    args[f"arg{i}_float64"] = struct.unpack("<d", stream.read(8))[0]
                elif arg_type == "BOOL":
                    args[f"arg{i}_bool"] = struct.unpack("<?", stream.read(1))[0]
                elif arg_type == "INT8":
                    args[f"arg{i}_int8"] = struct.unpack("<b", stream.read(1))[0]
                elif arg_type == "STRING":
                    # String with 1-byte length prefix
                    str_len = struct.unpack("<B", stream.read(1))[0]
                    args[f"arg{i}_string"] = stream.read(str_len).decode('utf-8', errors='ignore')
                elif arg_type == "VECTOR3":
                    args[f"arg{i}_vector3"] = BattleDecoder._read_vector3(stream)
                elif arg_type == "VECTOR2":
                    args[f"arg{i}_vector2"] = struct.unpack("<ff", stream.read(8))
                elif arg_type.startswith("ARRAY"):
                    # Array — read length + elements
                    arr_len = struct.unpack("<I", stream.read(4))[0]
                    args[f"arg{i}_array_len"] = arr_len
                    args[f"arg{i}_array_data"] = stream.read().hex()[:80]
                else:
                    # Unknown type — dump remaining as hex
                    args[f"arg{i}_{arg_type}"] = stream.read().hex()[:80]
                    break
        except Exception as e:
            args["parse_error"] = str(e)

        return args

    @staticmethod
    def _decode_map(stream: BytesIO, pkt_time: float) -> Dict:
        """Decode Map packet (type 0x0f)."""
        space_id = struct.unpack("<i", stream.read(4))[0]
        arena_id = struct.unpack("<i", stream.read(4))[0]
        name_len = struct.unpack("<b", stream.read(1))[0]
        name = stream.read(name_len).decode('utf-8', errors='ignore')

        return {
            "type": "map",
            "time": pkt_time,
            "space_id": space_id,
            "arena_id": arena_id,
            "name": name,
        }

    @staticmethod
    def _decode_entity_leave(stream: BytesIO, pkt_time: float) -> Dict:
        """Decode EntityLeave packet (type 0x4)."""
        entity_id = struct.unpack("<i", stream.read(4))[0]
        return {
            "type": "entity_leave",
            "time": pkt_time,
            "entity_id": entity_id,
        }

    @staticmethod
    def _decode_base_player(stream: BytesIO, pkt_time: float) -> Dict:
        """Decode BasePlayerCreate packet (type 0x0)."""
        entity_id = struct.unpack("<i", stream.read(4))[0]
        entity_type = struct.unpack("<h", stream.read(2))[0]
        value = BattleDecoder._read_binary_stream(stream)

        return {
            "type": "base_player_create",
            "time": pkt_time,
            "entity_id": entity_id,
            "entity_type": entity_type,
            "value": value.hex()[:80] if value else "",
        }

    @staticmethod
    def _decode_cell_player(stream: BytesIO, pkt_time: float) -> Dict:
        """Decode CellPlayerCreate packet (type 0x1)."""
        entity_id = struct.unpack("<i", stream.read(4))[0]
        space_id = struct.unpack("<i", stream.read(4))[0]
        unknown = struct.unpack("<h", stream.read(2))[0]
        vehicle_id = struct.unpack("<i", stream.read(4))[0]
        position = BattleDecoder._read_vector3(stream)
        direction = BattleDecoder._read_vector3(stream)
        value = BattleDecoder._read_binary_stream(stream)

        return {
            "type": "cell_player_create",
            "time": pkt_time,
            "entity_id": entity_id,
            "space_id": space_id,
            "vehicle_id": vehicle_id,
            "position": position,
            "direction": direction,
            "value": value.hex()[:80] if value else "",
        }

    @staticmethod
    def _decode_entity_enter(stream: BytesIO, pkt_time: float) -> Dict:
        """Decode EntityEnter packet (type 0x3)."""
        entity_id = struct.unpack("<i", stream.read(4))[0]
        return {
            "type": "entity_enter",
            "time": pkt_time,
            "entity_id": entity_id,
        }

    @staticmethod
    def _decode_nested_property(stream: BytesIO, pkt_time: float) -> Dict:
        """Decode NestedProperty packet (type 0x24)."""
        data = stream.read()
        return {
            "type": "nested_property",
            "time": pkt_time,
            "data": data.hex()[:80],
        }


# ===========================================================================
# BATTLE AWARENESS — Real-time game state tracker
# ===========================================================================

class BattleAwareness:
    """
    Tracks the real-time battle state by decoding BigWorld packets.

    Maintains:
    - All vehicles (enemies + allies) with positions, health, ammo, reload
    - Own vehicle state (position, health, ammo, reload, gun angles)
    - Spotted enemies list
    - Shot results history
    - Chat messages from teammates
    - Map/arena info

    This is the "eyes and ears" of the bot. It feeds data to the
    TargetingSystem and SmartBattleAI for decision-making.
    """

    def __init__(self):
        self.vehicles: Dict[int, TrackedVehicle] = {}
        self.own_vehicle: Optional[TrackedVehicle] = None
        self.own_entity_id: int = 0
        self.map_name: str = ""
        self.arena_id: int = 0
        self.shot_results: List[ShotResult] = []
        self.chat_messages: List[ChatMessage] = []
        self.weak_spots = WeakSpotDatabase()
        self._packet_count = 0
        self._last_update = time.time()

        # Callbacks
        self.on_enemy_spotted: Optional[Callable] = None
        self.on_enemy_destroyed: Optional[Callable] = None
        self.on_shot_result: Optional[Callable] = None
        self.on_chat_message: Optional[Callable] = None
        self.on_health_update: Optional[Callable] = None
        self.on_ammo_update: Optional[Callable] = None

    def process_packet(self, raw_data: bytes) -> Optional[Dict]:
        """Process a raw BigWorld packet and update battle state."""
        pkt = BattleDecoder.decode_single(raw_data)
        if not pkt:
            return None

        self._packet_count += 1
        self._last_update = time.time()

        # Dispatch to handler
        handler = {
            "position": self._handle_position,
            "entity_create": self._handle_entity_create,
            "entity_method": self._handle_entity_method,
            "entity_leave": self._handle_entity_leave,
            "map": self._handle_map,
            "base_player_create": self._handle_base_player,
            "cell_player_create": self._handle_cell_player,
        }.get(pkt["type"])

        if handler:
            handler(pkt)

        return pkt

    def process_packets(self, raw_data: bytes) -> List[Dict]:
        """Process multiple packets from a data buffer."""
        packets = BattleDecoder.decode_stream(raw_data)
        for pkt in packets:
            self._packet_count += 1
            handler = {
                "position": self._handle_position,
                "entity_create": self._handle_entity_create,
                "entity_method": self._handle_entity_method,
                "entity_leave": self._handle_entity_leave,
                "map": self._handle_map,
                "base_player_create": self._handle_base_player,
                "cell_player_create": self._handle_cell_player,
            }.get(pkt["type"])
            if handler:
                handler(pkt)
        return packets

    def _handle_position(self, pkt: Dict):
        """Handle position update packet."""
        eid = pkt["entity_id"]

        if eid not in self.vehicles:
            self.vehicles[eid] = TrackedVehicle(entity_id=eid)

        v = self.vehicles[eid]
        v.vehicle_id = pkt["vehicle_id"]
        v.position = pkt["position"]
        v.yaw = pkt["yaw"]
        v.pitch = pkt["pitch"]
        v.roll = pkt["roll"]
        v.last_position_update = time.time()
        v.last_seen = time.time()

        if eid == self.own_entity_id:
            self.own_vehicle = v

    def _handle_entity_create(self, pkt: Dict):
        """Handle entity creation (vehicle enters AOI)."""
        eid = pkt["entity_id"]
        v = TrackedVehicle(
            entity_id=eid,
            vehicle_id=pkt["vehicle_id"],
            position=pkt["position"],
            direction=pkt["direction"],
            last_seen=time.time(),
        )
        self.vehicles[eid] = v

        # If this is an enemy, trigger callback
        if v.is_enemy and self.on_enemy_spotted:
            self.on_enemy_spotted(v)

    def _handle_entity_method(self, pkt: Dict):
        """Handle entity method call (server → client)."""
        method_name = pkt.get("method_name", "")
        args = pkt.get("args", {})

        if method_name == "updateVehicleHealth":
            # (OBJECT_ID vehicle, INT16 health, INT8 ?, BOOL, BOOL)
            vid = args.get("arg0_object_id", 0)
            health = args.get("arg1_int16", 100)
            is_alive = args.get("arg4_bool", True)

            for v in self.vehicles.values():
                if v.vehicle_id == vid or v.entity_id == vid:
                    old_hp = v.health
                    v.health = health
                    v.is_alive = health > 0

                    if health <= 0 and old_hp > 0 and self.on_enemy_destroyed:
                        self.on_enemy_destroyed(v)
                    elif self.on_health_update:
                        self.on_health_update(v, old_hp, health)
                    break

        elif method_name == "updateVehicleGunReloadTime":
            # (OBJECT_ID vehicle, FLOAT32 reload_start, FLOAT32 reload_end)
            vid = args.get("arg0_object_id", 0)
            reload_start = args.get("arg1_float32", 0.0)
            reload_end = args.get("arg2_float32", 0.0)

            for v in self.vehicles.values():
                if v.vehicle_id == vid or v.entity_id == vid:
                    v.reload_start = reload_start
                    v.reload_end = reload_end
                    v.is_reloading = reload_end > reload_start
                    break

        elif method_name == "updateVehicleClipReloadTime":
            # (OBJECT_ID, FLOAT32, FLOAT32, BOOL)
            vid = args.get("arg0_object_id", 0)
            for v in self.vehicles.values():
                if v.vehicle_id == vid or v.entity_id == vid:
                    v.reload_start = args.get("arg1_float32", 0.0)
                    v.reload_end = args.get("arg2_float32", 0.0)
                    v.is_reloading = args.get("arg3_bool", False)
                    break

        elif method_name == "updateVehicleAmmo":
            # (OBJECT_ID, INT32, UINT16, UINT8, INT16, INT16)
            vid = args.get("arg0_object_id", 0)
            ammo_count = args.get("arg1_int32", 0)
            shell_type = args.get("arg2_uint16", 0)
            clip_size = args.get("arg3_uint8", 1)
            current = args.get("arg4_int16", 0)
            total = args.get("arg5_int16", 0)

            for v in self.vehicles.values():
                if v.vehicle_id == vid or v.entity_id == vid:
                    v.clip_size = clip_size
                    v.clip_current = current
                    if not v.ammo:
                        v.ammo = [total]
                    else:
                        v.ammo[0] = total

                    if self.on_ammo_update:
                        self.on_ammo_update(v)
                    break

        elif method_name == "updateOwnVehiclePosition":
            # (VECTOR3 position, VECTOR3 direction, FLOAT32, FLOAT32)
            pos = args.get("arg0_vector3")
            direction = args.get("arg1_vector3")

            if self.own_vehicle and pos:
                self.own_vehicle.position = pos
                self.own_vehicle.direction = direction or self.own_vehicle.direction
                self.own_vehicle.last_position_update = time.time()

        elif method_name == "showShotResults":
            # (ARRAY<UINT64>) — shot penetration results
            # Each UINT64 encodes: target_id + result_type + damage
            arr_len = args.get("arg0_array_len", 0)
            if arr_len > 0:
                raw = args.get("arg0_array_data", "")
                # Try to decode shot results
                result = ShotResult(timestamp=time.time())
                if arr_len > 0:
                    result.result_type = 2  # PIERCED (default)
                    result.result_name = SHOT_RESULT.get(2, "PIERCED")
                self.shot_results.append(result)

                if self.on_shot_result:
                    self.on_shot_result(result)

        elif method_name == "showVehicleDamageInfo":
            # (OBJECT_ID, UINT8, EXTRA_ID, OBJECT_ID, UINT8)
            target_id = args.get("arg0_object_id", 0)
            damage_type = args.get("arg1_uint8", 0)
            attacker_id = args.get("arg3_object_id", 0)

            # Track damage events
            logger.debug("Damage: %s → %s (type %d)", attacker_id, target_id, damage_type)

    def _handle_entity_leave(self, pkt: Dict):
        """Handle entity leaving AOI."""
        eid = pkt["entity_id"]
        if eid in self.vehicles:
            self.vehicles[eid].is_spotted = False
            self.vehicles[eid].last_seen = 0

    def _handle_map(self, pkt: Dict):
        """Handle map/arena info."""
        self.map_name = pkt.get("name", "")
        self.arena_id = pkt.get("arena_id", 0)
        logger.info("Map: %s (arena %d)", self.map_name, self.arena_id)

    def _handle_base_player(self, pkt: Dict):
        """Handle base player creation."""
        self.own_entity_id = pkt.get("entity_id", 0)
        if self.own_entity_id not in self.vehicles:
            self.vehicles[self.own_entity_id] = TrackedVehicle(entity_id=self.own_entity_id)
        self.own_vehicle = self.vehicles[self.own_entity_id]
        logger.info("Own vehicle: entity %d", self.own_entity_id)

    def _handle_cell_player(self, pkt: Dict):
        """Handle cell player creation."""
        eid = pkt.get("entity_id", 0)
        if eid not in self.vehicles:
            self.vehicles[eid] = TrackedVehicle(entity_id=eid)
        v = self.vehicles[eid]
        v.vehicle_id = pkt.get("vehicle_id", 0)
        v.position = pkt.get("position", Vector3())
        v.direction = pkt.get("direction", Vector3())
        v.last_seen = time.time()

        if eid == self.own_entity_id:
            self.own_vehicle = v

    # ===========================================================================
    # BATTLE STATE QUERIES
    # ===========================================================================

    def get_enemies(self, alive_only: bool = True) -> List[TrackedVehicle]:
        """Get all tracked enemies."""
        enemies = [v for v in self.vehicles.values() if v.is_enemy]
        if alive_only:
            enemies = [e for e in enemies if e.is_alive]
        return enemies

    def get_spotted_enemies(self) -> List[TrackedVehicle]:
        """Get enemies that are currently spotted (visible)."""
        return [v for v in self.vehicles.values()
                if v.is_enemy and v.is_spotted and v.is_alive and v.last_seen > 0]

    def get_nearest_enemy(self, max_distance: float = float('inf')) -> Optional[TrackedVehicle]:
        """Find the nearest spotted enemy."""
        if not self.own_vehicle:
            return None

        spotted = self.get_spotted_enemies()
        nearest = None
        nearest_dist = max_distance

        for enemy in spotted:
            dist = self.own_vehicle.position.distance_to(enemy.position)
            if dist < nearest_dist:
                nearest = enemy
                nearest_dist = dist

        return nearest

    def get_lowest_health_enemy(self) -> Optional[TrackedVehicle]:
        """Find the enemy with the lowest health (easy kill)."""
        spotted = self.get_spotted_enemies()
        if not spotted:
            return None
        return min(spotted, key=lambda e: e.health)

    def get_weakest_target(self) -> Optional[TrackedVehicle]:
        """
        Find the best target: lowest health × closest distance.
        Prioritizes easy kills and nearby enemies.
        """
        spotted = self.get_spotted_enemies()
        if not spotted:
            return None

        if not self.own_vehicle:
            return spotted[0]

        # Score = health / max_health * 0.5 + distance/max_dist * 0.5
        # Lower score = better target
        max_dist = 500.0  # normalization
        best = None
        best_score = float('inf')

        for enemy in spotted:
            hp_ratio = enemy.health / max(1, enemy.max_health)
            dist = self.own_vehicle.position.distance_to(enemy.position)
            dist_ratio = min(1.0, dist / max_dist)

            # Is enemy reloading? Lower priority (they can't shoot back)
            reload_penalty = 0.1 if enemy.is_reloading else 0.0

            score = hp_ratio * 0.4 + dist_ratio * 0.4 + reload_penalty
            if score < best_score:
                best = enemy
                best_score = score

        return best

    def get_enemy_facing(self, enemy: TrackedVehicle) -> str:
        """
        Determine which side of the enemy we're facing.
        Returns: 'front', 'side', or 'rear'
        """
        if not self.own_vehicle:
            return "front"

        # Calculate angle from enemy to us
        dx = self.own_vehicle.position.x - enemy.position.x
        dz = self.own_vehicle.position.z - enemy.position.z
        angle_to_us = math.atan2(dz, dx)

        # Enemy's facing direction (yaw)
        enemy_yaw = enemy.yaw

        # Relative angle
        rel_angle = angle_to_us - enemy_yaw
        # Normalize to [-pi, pi]
        rel_angle = ((rel_angle + math.pi) % (2 * math.pi)) - math.pi

        # Classify
        abs_angle = abs(rel_angle)
        if abs_angle < math.pi / 4:      # ±45°
            return "front"
        elif abs_angle < 3 * math.pi / 4: # ±135°
            return "side"
        else:
            return "rear"

    def get_ammo_count(self) -> int:
        """Get our current ammo count."""
        if self.own_vehicle and self.own_vehicle.ammo:
            return self.own_vehicle.ammo[0] if self.own_vehicle.ammo else 0
        return -1  # unknown

    def get_reload_status(self) -> Tuple[bool, float]:
        """
        Get our gun reload status.
        Returns: (is_reloading, seconds_remaining)
        """
        if self.own_vehicle and self.own_vehicle.is_reloading:
            now = time.time()
            remaining = max(0, self.own_vehicle.reload_end - now)
            return True, remaining
        return False, 0.0

    def get_health(self) -> int:
        """Get our current health."""
        if self.own_vehicle:
            return self.own_vehicle.health
        return -1

    def get_battle_summary(self) -> Dict:
        """Get a complete summary of the current battle state."""
        enemies = self.get_enemies(alive_only=True)
        spotted = self.get_spotted_enemies()
        own_hp = self.get_health()
        own_ammo = self.get_ammo_count()
        is_reloading, reload_time = self.get_reload_status()

        return {
            "own_health": own_hp,
            "own_ammo": own_ammo,
            "is_reloading": is_reloading,
            "reload_remaining": reload_time,
            "enemies_alive": len(enemies),
            "enemies_spotted": len(spotted),
            "total_vehicles": len(self.vehicles),
            "map": self.map_name,
            "packets_received": self._packet_count,
            "nearest_enemy_dist": (
                self.own_vehicle.position.distance_to(spotted[0].position)
                if self.own_vehicle and spotted else -1
            ),
        }


# ===========================================================================
# TARGETING SYSTEM — Aim at weak spots
# ===========================================================================

class TargetingSystem:
    """
    Targeting system that uses the BattleAwareness and WeakSpotDatabase
    to calculate optimal aim points.

    It:
    1. Picks the best target (lowest health × closest distance)
    2. Determines which side of the enemy we can hit
    3. Looks up the weak spots for that tank class and facing
    4. Calculates the aim point (yaw + pitch offsets)
    5. Tracks shot results for accuracy feedback
    """

    def __init__(self, awareness: BattleAwareness):
        self.awareness = awareness
        self.weak_spots = WeakSpotDatabase()
        self.current_target: Optional[TrackedVehicle] = None
        self.current_aim: Optional[Dict] = None
        self.shots_fired = 0
        self.shots_hit = 0
        self.shots_penetrated = 0
        self.damage_dealt = 0

        # Register callbacks
        self.awareness.on_shot_result = self._on_shot_result

    def acquire_target(self) -> Optional[TrackedVehicle]:
        """Find and lock onto the best target."""
        target = self.awareness.get_weakest_target()
        if target:
            self.current_target = target
            logger.info("Target acquired: entity %d (HP: %d, dist: %.0f)",
                       target.entity_id, target.health,
                       self.awareness.own_vehicle.position.distance_to(target.position)
                       if self.awareness.own_vehicle else 0)
        else:
            self.current_target = None
        return target

    def calculate_aim(self) -> Optional[Dict]:
        """
        Calculate the aim point for the current target.

        Returns dict with:
        - target_id: entity ID of the target
        - target_pos: Vector3 position of the target
        - distance: distance to target
        - facing: 'front', 'side', or 'rear'
        - weak_spot: name of the weak spot to aim at
        - yaw: required gun yaw
        - pitch: required gun pitch
        - yaw_offset: offset from center for weak spot
        - pitch_offset: offset from center for weak spot
        """
        if not self.current_target or not self.awareness.own_vehicle:
            return None

        target = self.current_target
        my_pos = self.awareness.own_vehicle.position
        target_pos = target.position

        # Calculate distance and base angles
        dx = target_pos.x - my_pos.x
        dz = target_pos.z - my_pos.z
        dy = target_pos.y - my_pos.y
        distance = math.sqrt(dx*dx + dz*dz + dy*dy)

        yaw = math.atan2(dz, dx)
        pitch = math.atan2(dy, math.sqrt(dx*dx + dz*dz))

        # Determine which side of the enemy we're facing
        facing = self.awareness.get_enemy_facing(target)

        # Get tank class from vehicle type (simplified)
        tank_class = self._guess_tank_class(target)

        # Get weak spot for this facing and class
        yaw_offset, pitch_offset, spot_name = self.weak_spots.get_aim_point(
            tank_class, facing, target_pos, my_pos
        )

        # Check if enemy is reloading (safe to shoot)
        is_target_reloading = target.is_reloading

        # Check our reload status
        is_reloading, reload_remaining = self.awareness.get_reload_status()

        self.current_aim = {
            "target_id": target.entity_id,
            "target_pos": target_pos,
            "distance": distance,
            "facing": facing,
            "weak_spot": spot_name,
            "tank_class": tank_class,
            "yaw": yaw,
            "pitch": pitch,
            "yaw_offset": yaw_offset,
            "pitch_offset": pitch_offset,
            "final_yaw": yaw + yaw_offset,
            "final_pitch": pitch + pitch_offset,
            "target_health": target.health,
            "target_reloading": is_target_reloading,
            "target_is_alive": target.is_alive,
            "can_shoot": not is_reloading and distance > 0,
            "own_reloading": is_reloading,
            "reload_remaining": reload_remaining,
            "aim_ready": not is_reloading,
        }

        return self.current_aim

    def should_shoot(self) -> bool:
        """Decide whether to fire now based on aim and battle state."""
        if not self.current_aim:
            return False

        # Can't shoot if reloading
        if self.current_aim.get("own_reloading", False):
            return False

        # Can't shoot if no ammo
        ammo = self.awareness.get_ammo_count()
        if ammo == 0:
            return False

        # Don't shoot if target is too far (low hit chance)
        if self.current_aim.get("distance", 999) > 500:
            return False

        # Don't shoot if target is dead
        if not self.current_aim.get("target_is_alive", False):
            return False

        # Good to shoot
        return True

    def _guess_tank_class(self, vehicle: TrackedVehicle) -> str:
        """Guess the tank class from available info."""
        # In a full implementation, this would use the tank type compact descriptor
        # from the Vehicle entity's compDescr property or playerVehicleTypeCompDescr
        # For now, use a simple heuristic based on health
        if vehicle.max_health > 1500:
            return "heavy"
        elif vehicle.max_health > 1000:
            return "medium"
        elif vehicle.max_health > 600:
            return "td"
        elif vehicle.max_health > 400:
            return "light"
        else:
            return "spg"

    def _on_shot_result(self, result: ShotResult):
        """Track shot results for accuracy statistics."""
        self.shots_fired += 1
        if result.result_type >= 2:  # PIERCED or better
            self.shots_hit += 1
            self.shots_penetrated += 1
        elif result.result_type >= 1:  # NON_PIERCING
            self.shots_hit += 1

        accuracy = (self.shots_hit / max(1, self.shots_fired)) * 100
        logger.debug("Shot result: %s | Accuracy: %.1f%% (%d/%d)",
                    result.result_name, accuracy, self.shots_hit, self.shots_fired)

    def get_stats(self) -> Dict:
        """Get targeting statistics."""
        return {
            "shots_fired": self.shots_fired,
            "shots_hit": self.shots_hit,
            "shots_penetrated": self.shots_penetrated,
            "accuracy": (self.shots_hit / max(1, self.shots_fired)) * 100,
            "penetration_rate": (self.shots_penetrated / max(1, self.shots_fired)) * 100,
        }


# ===========================================================================
# TEAM COMMUNICATOR — Chat and callouts
# ===========================================================================

class TeamCommunicator:
    """
    Handles teammate communication via the BigWorld Chat interface.

    Can:
    - Send chat messages to the team
    - Make tactical callouts (enemy spotted, need help, etc.)
    - Parse incoming chat from teammates
    - Respond to common commands

    Chat format (from Chat.def):
    - chatCommandFromClient: (INT64, UINT8, OBJECT_ID, INT64, INT16, STRING, STRING)
      - arg0: channel ID (INT64)
      - arg1: message type (UINT8) — 0=team, 1=all, 2=system
      - arg2: sender entity ID (OBJECT_ID)
      - arg3: receiver ID (INT64)
      - arg4: flags (INT16)
      - arg5: player name (STRING)
      - arg6: message text (STRING)
    """

    # Chat message types
    CHAT_TEAM = 0
    CHAT_ALL = 1
    CHAT_SYSTEM = 2

    # Callout messages
    CALLOUTS = {
        "enemy_spotted": "Enemy spotted at grid {grid}",
        "enemy_low_hp": "Enemy at {grid} is low HP — finish him!",
        "need_help": "Need help at grid {grid}!",
        "enemy_reloading": "Enemy reloading — push now!",
        "enemy_destroyed": "Target destroyed!",
        "flanking_left": "Pushing left flank",
        "flanking_right": "Pushing right flank",
        "defend_base": "Defending base!",
        "push_base": "Push enemy base!",
        "low_ammo": "Low ammo — careful",
        "low_hp": "Low HP — falling back",
        "enemy_behind": "Enemy behind us!",
        "good_shot": "Nice shot!",
        "thanks": "Thanks!",
        "regroup": "Regroup at {grid}",
    }

    # Tactical messages by situation
    TACTICAL_MESSAGES = [
        "Focus fire on the lowest HP enemy!",
        "Don't overextend — stay with the team",
        "Keep shooting — damage is damage",
        "Track them first, then shoot!",
        "Aim for the lower glacis!",
        "Side shots are easier to penetrate",
        "Watch for enemy reloads — push when they're reloading",
    ]

    def __init__(self, awareness: BattleAwareness, entity_id: int = 0):
        self.awareness = awareness
        self.entity_id = entity_id
        self.message_queue: List[Tuple[str, int]] = []  # (message, channel)
        self.last_message_time = 0
        self.message_cooldown = 5.0  # seconds between messages

        # Register callback for incoming chat
        self.awareness.on_chat_message = self._on_incoming_chat

    def send_team_message(self, message: str) -> bool:
        """Queue a message to send to the team chat."""
        now = time.time()
        if now - self.last_message_time < self.message_cooldown:
            return False

        self.message_queue.append((message, self.CHAT_TEAM))
        self.last_message_time = now
        logger.info("[Team Chat] %s", message)
        return True

    def send_all_message(self, message: str) -> bool:
        """Queue a message to send to all chat."""
        now = time.time()
        if now - self.last_message_time < self.message_cooldown:
            return False

        self.message_queue.append((message, self.CHAT_ALL))
        self.last_message_time = now
        logger.info("[All Chat] %s", message)
        return True

    def make_callout(self, callout_type: str, **kwargs) -> bool:
        """Make a tactical callout."""
        template = self.CALLOUTS.get(callout_type, callout_type)
        message = template.format(**kwargs)
        return self.send_team_message(message)

    def enemy_spotted_callout(self, enemy: TrackedVehicle) -> bool:
        """Callout when an enemy is spotted."""
        grid = self._pos_to_grid(enemy.position)
        return self.make_callout("enemy_spotted", grid=grid)

    def low_hp_callout(self, enemy: TrackedVehicle) -> bool:
        """Callout when an enemy is low HP."""
        grid = self._pos_to_grid(enemy.position)
        return self.make_callout("enemy_low_hp", grid=grid)

    def need_help_callout(self, position: Vector3) -> bool:
        """Callout for help."""
        grid = self._pos_to_grid(position)
        return self.make_callout("need_help", grid=grid)

    def _pos_to_grid(self, pos: Vector3) -> str:
        """Convert a position to a minimap grid reference (e.g. 'D5')."""
        # WoT maps are typically 1000x1000 units
        # Grid is usually 10x10 with letters A-J and numbers 1-10
        col = chr(ord('A') + int(pos.x / 100) % 10)
        row = int(pos.z / 100) % 10 + 1
        return f"{col}{row}"

    def _on_incoming_chat(self, msg: ChatMessage):
        """Handle incoming chat messages from teammates."""
        logger.info("[Chat] %s: %s", msg.sender_id, msg.message)

        # Simple response system
        msg_lower = msg.message.lower()
        if "help" in msg_lower:
            self.send_team_message("Coming to help!")
        elif "push" in msg_lower:
            self.send_team_message("Following push!")
        elif "defend" in msg_lower:
            self.send_team_message("Falling back to defend!")
        elif "focus" in msg_lower:
            self.send_team_message("Focusing target!")

    def get_outgoing_packets(self) -> List[bytes]:
        """Get queued chat messages as encoded packets to send to the server."""
        packets = []
        while self.message_queue:
            message, channel = self.message_queue.pop(0)

            # Encode chat command packet
            # chatCommandFromClient: (INT64, UINT8, OBJECT_ID, INT64, INT16, STRING, STRING)
            player_name = "Bot"  # In real use, this would be the account name
            msg_bytes = message.encode('utf-8')
            name_bytes = player_name.encode('utf-8')

            payload = struct.pack("<qBIqi",
                0,            # channel ID (INT64)
                channel,      # message type (UINT8)
                self.entity_id, # sender (OBJECT_ID)
                0,            # receiver (INT64)
                0,            # flags (INT16)
            )
            payload += struct.pack("<B", len(name_bytes)) + name_bytes
            payload += struct.pack("<B", len(msg_bytes)) + msg_bytes

            # Wrap in EntityMethod packet
            # type 0x8: [entity_id (uint32)] [message_id (uint32)] [binary_stream]
            inner = struct.pack("<II", self.entity_id, 3)  # method 3 = chatCommandFromClient
            inner += struct.pack("<I", len(payload)) + payload

            # Wrap in NetPacket header
            net_packet = struct.pack("<IIf", len(inner), PKT_ENTITY_METHOD, 0.0) + inner
            packets.append(net_packet)

        return packets

    def send_random_tactical(self) -> bool:
        """Send a random tactical message."""
        msg = random.choice(self.TACTICAL_MESSAGES)
        return self.send_team_message(msg)


# ===========================================================================
# SMART BATTLE AI — Tactical decision-making
# ===========================================================================

class SmartBattleAI:
    """
    The brain of the bot. Uses BattleAwareness, TargetingSystem,
    and TeamCommunicator to make tactical decisions.

    Decision loop (per game tick):
    1. Update battle state from incoming packets
    2. Check own status (health, ammo, reload)
    3. Acquire/validate target
    4. Calculate aim at weak spot
    5. Decide action: shoot, move, use consumable, communicate
    6. Execute action
    7. Send chat callouts when relevant
    """

    def __init__(self, awareness: BattleAwareness):
        self.awareness = awareness
        self.targeting = TargetingSystem(awareness)
        self.comms = TeamCommunicator(awareness)
        self.aggression = "very_aggressive"
        self.last_target_check = 0
        self.last_callout = 0
        self.battle_start = time.time()
        self.actions_log = []

    def tick(self) -> Dict:
        """
        Process one battle tick. Returns action decisions.

        Returns dict with:
        - action: 'shoot', 'aim', 'move', 'reload', 'use_consumable', 'wait'
        - target_id: entity ID of target (if shooting)
        - aim: aim dict from TargetingSystem
        - chat: message to send (if any)
        - status: current status summary
        """
        now = time.time()
        decisions = {}

        # Get battle state
        summary = self.awareness.get_battle_summary()
        decisions["status"] = summary

        # Check own status
        own_hp = summary["own_health"]
        own_ammo = summary["own_ammo"]
        is_reloading = summary["is_reloading"]
        reload_remaining = summary["reload_remaining"]

        # Low HP behavior
        if own_hp > 0 and own_hp < 100:
            decisions["action"] = "retreat"
            if now - self.last_callout > 10:
                self.comms.make_callout("low_hp")
                self.last_callout = now
            return decisions

        # No ammo
        if own_ammo == 0:
            decisions["action"] = "wait"
            if now - self.last_callout > 30:
                self.comms.make_callout("low_ammo")
                self.last_callout = now
            return decisions

        # Acquire/validate target
        if (not self.targeting.current_target or
            not self.targeting.current_target.is_alive or
            now - self.last_target_check > 5.0):
            self.targeting.acquire_target()
            self.last_target_check = now

            # Callout when new enemy spotted
            if self.targeting.current_target and now - self.last_callout > 8:
                self.comms.enemy_spotted_callout(self.targeting.current_target)
                self.last_callout = now

        if not self.targeting.current_target:
            # No target — move to find enemies
            decisions["action"] = "move"
            decisions["move_direction"] = "forward"  # push forward to find enemies
            return decisions

        # Calculate aim
        aim = self.targeting.calculate_aim()
        decisions["aim"] = aim

        if not aim:
            decisions["action"] = "wait"
            return decisions

        # Decision: shoot or aim
        if aim["aim_ready"] and self.targeting.should_shoot():
            # Fire!
            decisions["action"] = "shoot"
            decisions["target_id"] = aim["target_id"]
            decisions["weak_spot"] = aim["weak_spot"]
            decisions["facing"] = aim["facing"]
            decisions["distance"] = aim["distance"]

            # Callout for low HP enemy
            if aim.get("target_health", 100) < 200:
                if now - self.last_callout > 8:
                    enemy = self.targeting.current_target
                    self.comms.low_hp_callout(enemy)
                    self.last_callout = now
        elif is_reloading:
            decisions["action"] = "wait_reload"
            decisions["reload_remaining"] = reload_remaining

            # Callout when enemy is reloading
            if aim.get("target_reloading") and now - self.last_callout > 10:
                self.comms.make_callout("enemy_reloading")
                self.last_callout = now
        else:
            decisions["action"] = "aim"
            decisions["target_id"] = aim["target_id"]
            decisions["weak_spot"] = aim["weak_spot"]

        # Random tactical callout
        if now - self.last_callout > 30 and random.random() < 0.1:
            self.comms.send_random_tactical()
            self.last_callout = now

        return decisions

    def get_battle_report(self) -> Dict:
        """Generate a comprehensive battle report."""
        elapsed = time.time() - self.battle_start
        target_stats = self.targeting.get_stats()
        battle_state = self.awareness.get_battle_summary()

        return {
            "duration": elapsed,
            "own_health": battle_state["own_health"],
            "own_ammo": battle_state["own_ammo"],
            "enemies_alive": battle_state["enemies_alive"],
            "enemies_spotted": battle_state["enemies_spotted"],
            "packets_decoded": battle_state["packets_received"],
            "map": battle_state["map"],
            "shots_fired": target_stats["shots_fired"],
            "shots_hit": target_stats["shots_hit"],
            "shots_penetrated": target_stats["shots_penetrated"],
            "accuracy": target_stats["accuracy"],
            "penetration_rate": target_stats["penetration_rate"],
            "current_target": (
                self.targeting.current_target.entity_id
                if self.targeting.current_target else None
            ),
            "current_weak_spot": (
                self.targeting.current_aim.get("weak_spot")
                if self.targeting.current_aim else None
            ),
        }
